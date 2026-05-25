from __future__ import annotations

from pathlib import Path


def app_source_root() -> Path:
    return Path(__file__).resolve().parents[4] / "workspaces" / "workspace" / "app" / "emulebb-main" / "srchybrid"


def test_bar_shader_restores_empty_span_fallback_before_range_and_draw() -> None:
    source = (app_source_root() / "BarShader.cpp").read_text(encoding="utf-8", errors="ignore")
    header = (app_source_root() / "BarShader.h").read_text(encoding="utf-8", errors="ignore")

    assert "void EnsureSpanFallback();" in header
    assert "void CBarShader::EnsureSpanFallback()" in source
    assert "if (m_Spans.GetHeadPosition() == NULL)\n\t\tFill(0);" in source
    assert "int count = HALF(max(m_iHeight, 1));" in source
    assert "double increment = count > 1 ? piOverDepth / (count - 1) : 0.0;" in source
    assert "EnsureSpanFallback();\n\tconst uint64 uEndLookup = end != static_cast<uint64>(-1) ? end + 1 : end;" in source
    assert "POSITION endpos = m_Spans.FindFirstKeyAfter(uEndLookup);" in source
    assert "if (m_iWidth <= 0 || m_iHeight <= 0)\n\t\treturn;" in source
    assert "EnsureSpanFallback();\n\n\t//FillSolidRect()" in source
    assert "if (pos == NULL)\n\t\treturn;\n\tCOLORREF color = m_Spans.GetNextValue(pos);" in source
    assert "if (pos == NULL) {\n\t\trectSpan.left = rectSpan.right;" in source
