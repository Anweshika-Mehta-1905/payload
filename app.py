"""
Payload Obfuscation & Detection Evasion Simulator: Streamlit dashboard.

EDUCATIONAL USE ONLY. Operates exclusively on benign mock strings.
Run with:  streamlit run app.py
"""

import streamlit as st

from modules import encoder, obfuscator, report, scanner

APP_TITLE = "Payload Evasion Simulator"
DEFAULT_PAYLOAD = "mock_malware_string"
MAX_PAYLOAD_LEN = 200
TECHNIQUES = ["Base64", "ROT13", "XOR", "String Splitting", "Noise Insertion"]
PAGES = ["Encoder & Obfuscator", "Evasion Simulator", "Audit Report"]

DEFAULT_OPTIONS = {
    "xor_key": "simulator-key",
    "split_range": (1, 3),
    "noise_rate": 0.3,
    "seed": 1337,
    "techniques": TECHNIQUES,
}

st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")


# ---------------------------------------------------------------------------
# Transformation builders. Each returns (output_text, roundtrip_ok).
# ---------------------------------------------------------------------------

def _build_base64(payload: str, opts: dict):
    encoded = encoder.base64_encode(payload)
    return encoded, encoder.base64_decode(encoded) == payload


def _build_rot13(payload: str, opts: dict):
    encoded = encoder.rot13_transform(payload)
    return encoded, encoder.rot13_transform(encoded) == payload


def _build_xor(payload: str, opts: dict):
    key = opts["xor_key"]
    encoded = encoder.xor_encode(payload, key)
    return encoded, encoder.xor_decode(encoded, key) == payload


def _build_split(payload: str, opts: dict):
    low, high = opts["split_range"]
    chunks = obfuscator.split_string(payload, low, high, seed=opts["seed"])
    return obfuscator.chunks_to_expression(chunks), obfuscator.join_chunks(chunks) == payload


def _build_noise(payload: str, opts: dict):
    noisy = obfuscator.insert_noise(payload, opts["noise_rate"], seed=opts["seed"])
    return noisy, obfuscator.remove_noise(noisy) == payload


BUILDERS = {
    "Base64": _build_base64,
    "ROT13": _build_rot13,
    "XOR": _build_xor,
    "String Splitting": _build_split,
    "Noise Insertion": _build_noise,
}


def generate_variants(payload: str, options: dict):
    """Apply each selected transformation. Returns (variants, errors)."""
    variants, errors = [], []
    for name in options["techniques"]:
        try:
            output, roundtrip_ok = BUILDERS[name](payload, options)
            variants.append({"name": name, "output": output, "roundtrip": roundtrip_ok})
        except ValueError as exc:
            errors.append(f"{name}: {exc}")
    return variants, errors


def run_simulation(payload: str, variants: list):
    """Scan the original payload and every variant with the mock scanner."""
    original = scanner.scan(payload)
    results = [{**v, "scan": scanner.scan(v["output"])} for v in variants]
    return original, results


def status_badge(scan: dict) -> str:
    if scan["detected"]:
        return f":red[**Detected**]: matched {', '.join(scan['matches'])}"
    return ":green[**Bypassed**]: no blacklisted signature found"


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def render_sidebar():
    st.sidebar.title("🛡️ Evasion Simulator")
    st.sidebar.warning("Educational use only. Mock strings only. No real malware.")
    page = st.sidebar.radio("Navigate", PAGES, key="page")
    st.sidebar.divider()
    payload = st.sidebar.text_input(
        "Mock payload",
        value=DEFAULT_PAYLOAD,
        max_chars=MAX_PAYLOAD_LEN,
        key="payload",
        help="Benign placeholder text only, such as mock_malware_string.",
    )
    st.sidebar.caption("Static blacklist: " + ", ".join(scanner.DEFAULT_BLACKLIST))
    return page, payload


# ---------------------------------------------------------------------------
# Page 1: Encoder & Obfuscator
# ---------------------------------------------------------------------------

def page_encoder(payload: str):
    st.header("🔐 Encoder & Obfuscator")
    st.write(
        "Transform the mock payload from the sidebar. Each output is verified by "
        "decoding it back to the original."
    )

    left, right = st.columns(2)
    with left:
        techniques = st.multiselect(
            "Transformations", TECHNIQUES, default=TECHNIQUES, key="techniques"
        )
        xor_key = st.text_input("XOR key", value="simulator-key", max_chars=64, key="xor_key")
    with right:
        split_range = st.slider("String split chunk size", 1, 6, (1, 3), key="split_range")
        noise_rate = st.slider("Noise insertion rate", 0.05, 1.0, 0.3, 0.05, key="noise_rate")
        seed = st.number_input(
            "Random seed (for reproducibility)", min_value=0, max_value=99999,
            value=1337, key="seed",
        )

    options = {
        "xor_key": xor_key,
        "split_range": split_range,
        "noise_rate": noise_rate,
        "seed": int(seed),
        "techniques": techniques,
    }
    # Persist options so the simulator and report pages can reuse them.
    st.session_state["options"] = options

    if not payload.strip():
        st.info("Enter a mock payload in the sidebar to begin.")
        return

    st.subheader("Original payload")
    st.code(payload, language=None)

    variants, errors = generate_variants(payload, options)
    for err in errors:
        st.warning(err)

    for variant in variants:
        with st.container(border=True):
            st.markdown(f"**{variant['name']}**")
            st.code(variant["output"], language=None)
            if variant["roundtrip"]:
                st.success("Round-trip verified: decoding returns the original payload.")
            else:
                st.error("Round-trip failed: decoding did not return the original payload.")


# ---------------------------------------------------------------------------
# Page 2: Evasion Simulator
# ---------------------------------------------------------------------------

def page_simulator(payload: str):
    st.header("🧪 Evasion Simulator")
    st.write(
        "Each transformed variant is scanned by the static mock scanner. Compare the "
        "plaintext result with the transformed result to see where signatures fail."
    )

    if not payload.strip():
        st.info("Enter a mock payload in the sidebar to run the simulation.")
        return

    options = st.session_state.get("options", DEFAULT_OPTIONS)
    variants, errors = generate_variants(payload, options)
    for err in errors:
        st.warning(err)

    original, results = run_simulation(payload, variants)
    rate = report.compute_evasion_rate(results)

    col1, col2, col3 = st.columns(3)
    col1.metric("Original payload", original["status"])
    col2.metric("Variants tested", len(results))
    col3.metric("Evasion success rate", f"{rate:.0f}%")
    st.progress(rate / 100 if results else 0.0, text="Variants that bypassed static detection")

    if not original["detected"]:
        st.info(
            "The original payload is not on the blacklist, so there is nothing to evade. "
            "Include a term such as `mock_malware` in the sidebar payload to see the effect."
        )

    st.subheader("Original vs. obfuscated")
    left, right = st.columns([1, 2])
    with left:
        st.markdown("**Original payload**")
    with right:
        st.code(payload, language=None)
        st.markdown(status_badge(original))
    st.divider()

    for result in results:
        left, right = st.columns([1, 2])
        with left:
            st.markdown(f"**{result['name']}**")
            st.markdown(status_badge(result["scan"]))
        with right:
            st.code(result["output"], language=None)
        st.divider()


# ---------------------------------------------------------------------------
# Page 3: Audit Report
# ---------------------------------------------------------------------------

def page_report(payload: str):
    st.header("📄 Audit Report")
    st.write(
        "Compile the current simulation into a Markdown audit report, including "
        "recommendations for moving from static to behavioral detection."
    )

    if not payload.strip():
        st.info("Enter a mock payload in the sidebar before compiling a report.")
        return

    if st.button("🧾 Compile audit report", type="primary"):
        options = st.session_state.get("options", DEFAULT_OPTIONS)
        variants, _ = generate_variants(payload, options)
        original, results = run_simulation(payload, variants)
        st.session_state["report_md"] = report.build_report(payload, original, results)

    if "report_md" in st.session_state:
        md = st.session_state["report_md"]
        st.download_button(
            label="⬇️ Download Markdown report",
            data=md,
            file_name="evasion_audit_report.md",
            mime="text/markdown",
        )
        with st.expander("Preview report", expanded=True):
            st.markdown(md)
        st.caption("Recompile after changing the payload or options to refresh the report.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    page, payload = render_sidebar()
    st.title(APP_TITLE)

    if page == "Encoder & Obfuscator":
        page_encoder(payload)
    elif page == "Evasion Simulator":
        page_simulator(payload)
    else:
        page_report(payload)


if __name__ == "__main__":
    main()
