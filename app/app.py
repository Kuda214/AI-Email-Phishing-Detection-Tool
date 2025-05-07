import streamlit as st
from helper_predict import predict_email

st.set_page_config(page_title="Phishing Email Detector", layout="wide")

st.markdown("""
<style>
.stApp {background: #fff;}
h1, .main-pred, .ai-header {color:#181a1b;}
.stTabs [role="tablist"] {background-color: #f3f6fb;}
.stTabs [role="tablist"] button {background: #fff !important; font-weight:bold !important; color:#232629 !important;}
.stTabs [role="tablist"] button[aria-selected="true"] {background: #eaebff !important; color:#5b5b5f !important; border-bottom:2px solid #EA4C89;}
.stButton button {background:#fff; color:#232629; font-weight:600;}
.stButton button:hover {color:#EA4C89;}
.explain-box {
    background: #f7f7fa;
    border: 2px solid #eee;
    border-radius: 7px;
    max-height: 240px;
    min-height: 180px;
    overflow-y: auto;
    padding: 18px 16px 10px 16px;
    margin: 0 0 18px 0;
    font-size: 1.09em;
    color: #232629;
}
.orange-mark {background:#ff9800;color:#181a1b; border-radius:4px; padding:1px 5px;}
.codeword {background:#232629; color:#f6f6f6; border-radius:3px; margin:0 2px;}
.sender-meta {font-weight:bold;color:#ff9800;}
.right-info-box {
    background: #fff6e7;
    border: 2px solid #dda300;
    border-radius: 9px;
    min-height: 250px;
    min-width: 230px; max-width:360px;
    padding: 20px 20px 14px 22px;
    font-size: 1em;
    color: #000;
    margin-left: 15px;
    margin-top: 12px;
    box-shadow: 0 0 6px #eee;
    position: relative;
}
.infobox-title {
    font-size: 1.12em;
    font-weight: bold;
    color: #c17200;
    letter-spacing:0.3px;
    margin-bottom: .34em;
}
.infobox-pn {
    color:#e26210; font-weight:700;font-size:1.07em; margin-right: 0.29em;
}
.restart-topbtn {
    position: absolute;
    top:18px; right:12px;
}
</style>
""", unsafe_allow_html=True)


# --- App title and subtitle
st.markdown(
    "<h1 style='margin-bottom:0.4em; font-weight: 800; font-size: 2.3rem; color:#181a1b;'>Phishing Email Detector (AI-powered)</h1>",
    unsafe_allow_html=True
)
st.markdown(
    "<div style='font-size:1.08em; color:#26282c; margin-bottom:0.76em; font-weight:500;'>"
    "Upload or paste an email. The app will highlight suspicious words and explain the AI's decision."
    "</div>",
    unsafe_allow_html=True
)

# --- Use session state for result management ---
if "result_shown" not in st.session_state:
    st.session_state["result_shown"] = False
if "run_analysis" not in st.session_state:
    st.session_state["run_analysis"] = False
if "email_text" not in st.session_state:
    st.session_state["email_text"] = ""

main_col, info_col = st.columns([0.7, 0.3], gap="large")

with info_col:
    style_restart = "float:right; margin-top:-8px; margin-right:-5px; padding:.4em .8em .4em .8em; border:0; border-radius:5px; color:#fff; background:#c17200; font-weight:700; font-size:1.09em; letter-spacing:1px;"
    if st.session_state["result_shown"]:
        if st.button("Restart", key="restartbtn", help="Restart and test a new email", use_container_width=True):
            st.session_state["result_shown"] = False
            st.session_state["run_analysis"] = False
            st.session_state["email_text"] = ""
            st.experimental_rerun()

    st.markdown("""<div class='right-info-box'>            
        # About the numbers:
                    Each highlighted word is shown with a number (weight):
        <ul>
        <li>Num > 0 : Strongly indicates phishing. </li>
        <li>Num < 0 : Strongly indicates legitimate. </li>
        <li>Near 0: little effect on the prediction.</li>
        </ul>
        The larger the number (in either direction), 
        the more the word influences the AI's
        decision for this email.
        </>"""
                , unsafe_allow_html=True)
    st.markdown("<div class='infobox-title'>Info Box: AI Explanation</div>", unsafe_allow_html=True)
    st.markdown("""
    <ul style='padding-left:1.1em; font-size:1.03em; margin-bottom:0; color:#000'>
      <li><strong>Confidence Score</strong>: Probability (0%-100%) that this is phishing (AI-calculated).</li>
      <li><strong>Orange Highlight</strong>: Word or phrase the model associates most with phishing.</li>
      <li><strong>Word Weights</strong>: Show how strongly each term pushes prediction toward phishing (positive) or legitimate (negative).</li>
    </ul>
    <hr style='margin:5px 0'>
    """, unsafe_allow_html=True)
    st.markdown("<div style='font-size:1em; color:#e26210; font-weight:700; margin-bottom:2px;'>Top Suspicious Words:</div>", unsafe_allow_html=True)
    if st.session_state.get("result_shown", False) and "global_phish_terms" in st.session_state:
        st.markdown(
            "<ol start='1'>" +
            ''.join([f"<li class='infobox-pn'>{word}</li>" for word in st.session_state["global_phish_terms"][:8]]) +
            "</ol>",
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            "<div style='font-size:0.97em; color:#bba561; margin-top:5px;'>Run a prediction to see top words here.</div>",
            unsafe_allow_html=True
        )
    st.markdown(
        "<div style='font-size:0.95em; color:#222629; margin-top:6px;'>Highest positive number = most suspicious for phishing.</div>",
        unsafe_allow_html=True
    )
    st.markdown("</div>", unsafe_allow_html=True)


with main_col:
    if not st.session_state["result_shown"]:
        tab_upload, tab_paste = st.tabs(["Upload .txt File", "Paste Email"])
        email_text, run_analysis = None, False
        with tab_upload:
            uploaded_file = st.file_uploader("Upload your email (.txt file)", type=["txt"])
            if uploaded_file:
                file_text = uploaded_file.read().decode("utf-8", errors="replace")
                if st.button("Submit", key="uploadbtn"):
                    st.session_state["email_text"] = file_text
                    st.session_state["run_analysis"] = True
        with tab_paste:
            pasted = st.text_area("Paste email content below", key="pastebox", height=135)
            if st.button("Submit", key="pastebtn"):
                st.session_state["email_text"] = pasted
                st.session_state["run_analysis"] = bool(pasted.strip())
    else:
        # Don't show inputs/tabs after result shown!
        pass

    # Show prediction/results
    if st.session_state.get("run_analysis", False) and st.session_state["email_text"].strip():
        st.write("---")
        with st.spinner("Analyzing..."):
            (result, confidence, top_features, sender,
             highlighted, global_phish_terms) = predict_email(st.session_state["email_text"])
        st.session_state["result_shown"] = True
        st.session_state["run_analysis"] = False
        st.session_state["global_phish_terms"] = global_phish_terms

        pred_style = "color:#e04636;font-weight:900;" if result == "phishing" else "color:#18874b;font-weight:900;"
        # Main prediction and confidence score, compact
        st.markdown(f"""
        <div class='main-pred' style='font-size:2.8rem; {pred_style}; margin-bottom:0.3em;'>{result.upper()}</div>
        <div style='font-size:1.07em; color:#888; font-weight:500;'>Confidence Score:</div>
        <div style='font-size:2.25rem; font-weight:800; color:#232629; border-radius:8px; padding:0.07em 0.75em; background:#f9f9f9; display:inline-block; margin-bottom:0.7em;'>
            {confidence}%
        </div>
        """, unsafe_allow_html=True)

        st.markdown(
            "<div class='explain-box'>" +
            "<b>Email</b> <span style='font-weight:500;'>(orange = highly suspicious):</span><br><br>" +
            f"<div style='white-space: pre-wrap;line-height:1.65;font-size:1.058em;'>{highlighted}</div><hr style='margin:8px 2px'>" +
            "<b>Top words influencing the decision:</b>" +
            "<ol style='margin-bottom:0'>" +
            ''.join([f"<li><span class='orange-mark'>{w}</span> <span class='codeword'>{weight:+.2f}</span></li>"
                     for w, weight in top_features]) +
            "</ol></div>",
            unsafe_allow_html=True
        )

        st.markdown(
            "<hr/><div style='color:#bbb;font-size:0.98em;padding-top:10px;'>University of Pretoria — COS720 AI Phishing Email Detector Prototype.</div>",
            unsafe_allow_html=True
        )