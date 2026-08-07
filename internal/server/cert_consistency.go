package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	mycrypto "github.com/ocoj/ddns-manager/internal/crypto"
	"github.com/ocoj/ddns-manager/internal/store"
)

// S9 (v1.6.70): keep a certificate bundle self-consistent before it is pushed.
//
// Background: LoadCertBundle's self-heal only recomputes meta.hash; nothing on
// the heartbeat path regenerates cert.pfx. An external writer (e.g. a stray
// acme.sh cron or a manual `acme.sh --renew`) can therefore overwrite the PEMs
// while leaving the PFXs stale, and the Manager would push "new PEM + old PFX"
// to agents. Windows agents derive the IIS thumbprint from the PFX, so IIS ends
// up re-binding the OLD certificate. Production had exactly this state.
//
// Invariants: I12 (content-level, not mtime), I17 (no mtime proxies),
// I18 (per-bundle serialisation), I19 (leaf identity is the hard criterion;
// chain differences are informational), I20 (rebuild source is fullchain),
// I22 (reload inside the lock), I23/I25 (state-change dedup for audits).

type pfxVerdict int

const (
	pfxConsistent pfxVerdict = iota
	pfxNeedsRebuild
	pfxUnverifiable
)

func (v pfxVerdict) String() string {
	switch v {
	case pfxConsistent:
		return "consistent"
	case pfxNeedsRebuild:
		return "needs_rebuild"
	default:
		return "unverifiable"
	}
}

// candidatePFXPasswords returns the deduplicated, non-empty password candidates
// in precedence order (bundle → meta → default), matching the inheritance order
// used by acme.UpdateCertMeta.
func candidatePFXPasswords(b *store.CertBundle, meta map[string]interface{}) []string {
	var out []string
	seen := map[string]bool{}
	add := func(pw string) {
		if pw == "" || seen[pw] {
			return
		}
		seen[pw] = true
		out = append(out, pw)
	}
	if b != nil {
		add(b.PFXPassword)
	}
	if meta != nil {
		if pw, ok := meta["pfx_password"].(string); ok {
			add(pw)
		}
	}
	add(mycrypto.DefaultPFXPassword)
	return out
}

// decodePFXWithCandidates tries every password candidate and returns the leaf,
// the CA chain length, how many candidates were consumed, and the last error.
func decodePFXWithCandidates(data []byte, pws []string) (*x509.Certificate, int, int, error) {
	var lastErr error
	for i, pw := range pws {
		leaf, cas, err := mycrypto.ParsePFXLeafChain(data, pw)
		if err == nil && leaf != nil {
			return leaf, len(cas), i + 1, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable password candidate")
	}
	return nil, 0, len(pws), lastErr
}

func leafDER(pemData []byte) []byte {
	chain := mycrypto.ParseCertChainPEM(pemData)
	if len(chain) == 0 {
		return nil
	}
	return chain[0].Raw
}

// checkBundlePFXConsistency implements the three-state, content-level check.
// The hard criterion is leaf-DER equality across fullchain.pem, cert.pem and
// both PFX containers (I19). Chain-length differences are informational only:
// the on-disk chain length depends on which code path last generated the PFX
// (UpdateCertMeta → leaf-only, handleSetCertPFXPassword → full chain), so making
// it a hard criterion would cause a rebuild after every renewal.
func (s *Server) checkBundlePFXConsistency(b *store.CertBundle, meta map[string]interface{}) (pfxVerdict, string, bool) {
	if b == nil || len(b.Files) == 0 {
		return pfxUnverifiable, "bundle 为空", false
	}
	fcPEM := b.Files["fullchain.pem"]
	certPEM := b.Files["cert.pem"]
	keyPEM := b.Files["privkey.pem"]
	if (len(fcPEM) == 0 && len(certPEM) == 0) || len(keyPEM) == 0 {
		return pfxUnverifiable, "缺少 fullchain.pem/cert.pem 或 privkey.pem，无法判定应然内容", false
	}

	legacy, hasLegacy := b.Files["cert.pfx"]
	modern, hasModern := b.Files["cert-modern.pfx"]
	if !hasLegacy || len(legacy) == 0 || !hasModern || len(modern) == 0 {
		return pfxNeedsRebuild, "cert.pfx 或 cert-modern.pfx 缺失", false
	}

	p1 := leafDER(fcPEM)
	p2 := leafDER(certPEM)
	authoritative := p1
	if authoritative == nil {
		authoritative = p2
	}
	if authoritative == nil {
		return pfxUnverifiable, "PEM 中无有效证书", true
	}
	if p1 != nil && p2 != nil && !bytes.Equal(p1, p2) {
		return pfxNeedsRebuild, "fullchain.pem 与 cert.pem 的叶证书不一致", false
	}

	pws := candidatePFXPasswords(b, meta)
	for _, item := range []struct {
		name string
		data []byte
	}{{"cert.pfx", legacy}, {"cert-modern.pfx", modern}} {
		leaf, _, _, err := decodePFXWithCandidates(item.data, pws)
		if err != nil {
			return pfxUnverifiable, fmt.Sprintf("%s 无法解码: %s", item.name, mycrypto.ClassifyPFXError(err)), true
		}
		if !bytes.Equal(leaf.Raw, authoritative) {
			return pfxNeedsRebuild, fmt.Sprintf("%s 的叶证书与 PEM 不一致", item.name), false
		}
	}
	return pfxConsistent, "", false
}

// consistencySignature captures everything that should trigger at most one audit
// per state change (I23/I25): verdict, reason, leaf identities and chain lengths.
func consistencySignature(b *store.CertBundle, meta map[string]interface{}, v pfxVerdict, reason string) string {
	parts := []string{v.String(), reason}
	if b == nil {
		return strings.Join(parts, "|")
	}
	if chain := mycrypto.ParseCertChainPEM(b.Files["fullchain.pem"]); len(chain) > 0 {
		h := sha256.Sum256(chain[0].Raw)
		parts = append(parts, "fc="+hex.EncodeToString(h[:8])+fmt.Sprintf("/%d", len(chain)))
	}
	for _, name := range []string{"cert.pfx", "cert-modern.pfx"} {
		data := b.Files[name]
		if len(data) == 0 {
			continue
		}
		if leaf, caLen, _, err := decodePFXWithCandidates(data, candidatePFXPasswords(b, meta)); err == nil && leaf != nil {
			h := sha256.Sum256(leaf.Raw)
			parts = append(parts, name+"="+hex.EncodeToString(h[:8])+fmt.Sprintf("/%d", caLen+1))
		} else {
			parts = append(parts, name+"=undecodable")
		}
	}
	return strings.Join(parts, "|")
}

// auditBundleConsistency emits at most one audit per state change (I23).
func (s *Server) auditBundleConsistency(name string, b *store.CertBundle, meta map[string]interface{}, v pfxVerdict, reason string, hard bool) {
	sig := consistencySignature(b, meta, v, reason)
	s.pfxAuditMu.Lock()
	if s.pfxAuditSig == nil {
		s.pfxAuditSig = map[string]string{}
	}
	prev, seen := s.pfxAuditSig[name]
	if seen && prev == sig {
		s.pfxAuditMu.Unlock()
		return
	}
	s.pfxAuditSig[name] = sig
	s.pfxAuditMu.Unlock()

	if s.logMgr == nil {
		return
	}
	detail := fmt.Sprintf("bundle=%s %s", name, reason)
	switch {
	case v == pfxUnverifiable:
		// v1.6.70 B4: 按原因分级 —— 无法解码/重载失败/重建失败属错误（需要
		// 人工介入），而"缺少可判定的源文件"只属警告（无法判定应然内容）。
		// 两者都已按状态变更去重，因此不会按心跳刷屏（I15/I23）。
		lvl := "warning"
		if hard {
			lvl = "error"
		}
		s.logMgr.Log("cert", "证书一致性不可判定", detail, lvl)
	case v == pfxNeedsRebuild:
		s.logMgr.Log("cert", "证书内容不一致", detail, "warning")
	default:
		// Leaves are identical. Chain-length differences are informational only
		// (I19) but are still surfaced once per state change: the on-disk chain
		// length depends on which code path last generated the PFX.
		if fl, l1, l2, ok := chainLengths(b, meta); ok && (fl != l1 || fl != l2) {
			s.logMgr.Log("cert", "PFX 链长与 fullchain 不同",
				fmt.Sprintf("bundle=%s fullchain=%d cert.pfx=%d cert-modern.pfx=%d（叶证书一致，不影响功能；建议统一证书源）",
					name, fl, l1, l2), "warning")
			return
		}
		if seen {
			s.logMgr.Log("cert", "证书一致性恢复", detail, "info")
			return
		}
		s.logMgr.Log("cert", "证书一致性", detail, "info")
	}
}

// chainLengths returns the certificate count of fullchain.pem and of each PFX
// container (leaf included). ok=false when a length cannot be determined.
func chainLengths(b *store.CertBundle, meta map[string]interface{}) (fcLen, legacyLen, modernLen int, ok bool) {
	if b == nil {
		return 0, 0, 0, false
	}
	fcLen = len(mycrypto.ParseCertChainPEM(b.Files["fullchain.pem"]))
	if fcLen == 0 {
		return 0, 0, 0, false
	}
	pws := candidatePFXPasswords(b, meta)
	for _, item := range []struct {
		name string
		dst  *int
	}{{"cert.pfx", &legacyLen}, {"cert-modern.pfx", &modernLen}} {
		data := b.Files[item.name]
		if len(data) == 0 {
			continue
		}
		if _, caLen, _, err := decodePFXWithCandidates(data, pws); err == nil {
			*item.dst = caLen + 1
		}
	}
	return fcLen, legacyLen, modernLen, true
}

// emitRebuildAudit logs an actual rebuild (rare; converges after one pass).
func (s *Server) emitRebuildAudit(name, reason string) {
	if s.logMgr == nil {
		return
	}
	s.logMgr.Log("cert", "已重建双 PFX",
		fmt.Sprintf("bundle=%s 检测到 PEM/PFX 不一致(%s)，已按磁盘 fullchain.pem 重建双 PFX", name, reason), "warning")
}

// rebuildBundlePFX regenerates both PFX containers from the authoritative
// fullchain.pem + privkey.pem (I20) and normalises cert.pem to leaf-only form.
func (s *Server) rebuildBundlePFX(b *store.CertBundle, meta map[string]interface{}) error {
	fc := b.Files["fullchain.pem"]
	key := b.Files["privkey.pem"]
	if len(fc) == 0 || len(key) == 0 {
		return fmt.Errorf("缺少 fullchain.pem 或 privkey.pem")
	}
	pws := candidatePFXPasswords(b, meta)
	if len(pws) == 0 {
		return fmt.Errorf("无可用 PFX 密码候选")
	}
	pw := pws[0]

	legacy, err := mycrypto.GeneratePFX(fc, key, pw)
	if err != nil {
		return fmt.Errorf("生成 Legacy PFX: %w", err)
	}
	modern, err := mycrypto.GeneratePFXModern(fc, key, pw)
	if err != nil {
		return fmt.Errorf("生成 Modern PFX: %w", err)
	}
	b.Files["cert.pfx"] = legacy
	b.Files["cert-modern.pfx"] = modern
	if chain := mycrypto.ParseCertChainPEM(fc); len(chain) > 0 {
		b.Files["cert.pem"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0].Raw})
	}
	if b.PFXPassword == "" {
		b.PFXPassword = pw
	}
	return s.store.SaveCertBundle(b)
}

// ensureBundlePFXFresh is the heartbeat-path entry point. It returns the bundle
// the caller must use for encFiles and CertUpdate.CertHash (I16/I22): either the
// original one, a reloaded one, or a rebuilt one.
//
// Ordering: it runs after LoadCertBundle succeeded and before the matched check
// and the CertUpdate construction, so the refreshed hash is used everywhere.
func (s *Server) ensureBundlePFXFresh(name string, b *store.CertBundle) *store.CertBundle {
	if b == nil {
		return b
	}
	meta, err := s.store.LoadCertMeta(name)
	if err != nil || meta == nil {
		return b // 无 meta 无法判定作用域，保持原行为
	}
	if is, _ := meta["acme"].(bool); !is {
		return b // I7/R21：用户上传证书不触碰
	}

	verdict, reason, hard := s.checkBundlePFXConsistency(b, meta)
	if verdict != pfxNeedsRebuild {
		s.auditBundleConsistency(name, b, meta, verdict, reason, hard)
		return b
	}

	// I18/R22: serialise per bundle. The pre-lock check above is only a fast
	// path to avoid taking the lock for already-consistent bundles.
	unlock := s.lockBundleRebuild(name)
	defer unlock()

	// I22: must reload inside the lock — the in-memory copy may already be stale
	// (another heartbeat rebuilt the bundle between our load and this lock).
	b2, err := s.store.LoadCertBundle(name)
	if err != nil {
		s.auditBundleConsistency(name, b, meta, pfxUnverifiable, "锁内重载失败: "+err.Error(), true)
		return b
	}
	verdict2, reason2, hard2 := s.checkBundlePFXConsistency(b2, meta)
	if verdict2 != pfxNeedsRebuild {
		s.auditBundleConsistency(name, b2, meta, verdict2, reason2, hard2)
		return b2
	}

	if err := s.rebuildBundlePFX(b2, meta); err != nil {
		s.auditBundleConsistency(name, b2, meta, pfxUnverifiable, "重建失败: "+err.Error(), true)
		return b2
	}
	s.emitRebuildAudit(name, reason2)
	s.auditBundleConsistency(name, b2, meta, pfxConsistent, "", false)
	return b2
}
