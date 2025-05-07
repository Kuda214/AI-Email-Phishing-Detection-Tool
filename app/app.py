import streamlit as st
from helper_predict import predict_email

st.set_page_config(page_title="Phishing Email Detector", layout="wide")
st.markdown("""
<style>
.stApp {background: #fff; color:#333}
.stTabs [role="tablist"] {background-color: #f3f6fb;}
.stTabs [role="tablist"] button {background: #fff !important; font-weight:bold !important; color:#232629 !important;}
.stTabs [role="tablist"] button[aria-selected="true"] {background: #eaebff !important; color:#5b5b5f !important; border-bottom:2px solid #EA4C89;}
.stButton button {background:#b50e70; color:#232629; font-weight:600; width:120px; font-weight: bold; color:#fff;}
.stButton button:hover {color:#EA4C89;}
.info-box {
    background: #fff8ee;
    border: 2px solid #dda300;
    border-radius: 12px;
    min-height: 200px;
    max-width: 99%;
    padding: 18px 22px 12px 20px;
    font-size: 1.05em;
    color: #212121;
}
.info-title {
    font-size: 1.15em;
    font-weight: bold;
    color: #c17200;
    margin-bottom: .32em;
}
.main-prediction {
    font-size:2.6rem;
    font-weight:900;
    letter-spacing:1.5px;
    margin-bottom:0.18em;
}
.legit-green {color:#18874b;}
.phishing-red {color:#e04636;}
.bigscore {
    font-size:2.05rem;
    font-weight:800;
    display:block;
    margin-bottom:13px;
    color:#232629;
    background:#f5f8fa;
    border-radius:9px;
    padding:8px 20px 7px 17px;
}
.orange-mark {background:#ff9800;color:#181a1b; border-radius:3px; padding:1px 5px;}
.green-mark {background:#abdfbc;color:#18291e; border-radius:3px; padding:1px 5px;}
.codeword {background:#232629; color:#f6f6f6; border-radius:3px; margin:0 2px;}
.infobox-pn {color:#e26210; font-weight:700;font-size:1.13em; margin-right:0.35em;}
ul.infodots {margin-left:0.4em;}
</style>
""", unsafe_allow_html=True)

st.markdown(
    "<h1 style='margin-bottom:0.2em; font-weight:900; font-size: 2.2rem; color:#181a1b;'>Phishing Email Detector (AI-powered)</h1>",
    unsafe_allow_html=True
)
st.markdown(
    "<div style='font-size:1.10em; color:#26282c; margin-bottom:0.9em; font-weight:500;'>"
    "Upload or paste an email. The app highlights suspicious words and explains the AI's decision. "
    "</div>",
    unsafe_allow_html=True
)

if "result_shown" not in st.session_state:
    st.session_state["result_shown"] = False
if "run_analysis" not in st.session_state:
    st.session_state["run_analysis"] = False
if "email_text" not in st.session_state:
    st.session_state["email_text"] = ""

main_col, info_col = st.columns([0.7, 0.3], gap="large")

with info_col:
    st.markdown("""<div class='info-box'>
                 <div style='font-size:0.97em;margin:8px 0 2px 0;color:#333; font-weight:500;'>How to read the weights:</div>
                <ul style='margin-bottom:0;'>
                <li><b>Positive</b> (e.g. <span style="color:#e04636">+2.57</span>): Phishing.</li>
                <li><b>Negative</b> (e.g. <span style="color:#18874b">-2.57</span>): Legitimate.</li>
                <li><b>Word Weights</b>: Higher positive = more suspicious for phishing; higher negative = more likely legitimate.</li>
                </ul>
                """, unsafe_allow_html=True)
    st.markdown("<div class='info-title'>Info Box: How to read the results</div>", unsafe_allow_html=True)

    if st.session_state.get("result_shown", False) and "last_pred_result" in st.session_state:
        pred = st.session_state["last_pred_result"]
        conf = st.session_state["last_conf"]
        result_class = "phishing-red" if pred == "phishing" else "legit-green"
        st.markdown(f"<div class='main-prediction {result_class}' style='font-size:1.35rem'>{pred.upper()}</div>", unsafe_allow_html=True)
        st.markdown(f"<span style='color:#444; font-size:1em;'>Confidence: <span class='bigscore' style='font-size:1.02rem;padding:1px 12px;'>{conf}%</span></span>", unsafe_allow_html=True)

    st.markdown("""
    <ul class='infodots' style='font-size:1.07em; margin-bottom:0; color:#333;'>
      <li><b>Confidence Score</b>: Probability (0%-100%) this is phishing (AI-calculated).</li>
      <li><b>Orange Highlight</b>: Word/phrase the model associates most with phishing (weight &gt; 0).</li>
      <li><b>Green Highlight</b>: Word/phrase strongly associated with legitimate emails (weight &lt; 0).</li>
    </ul>
   
    <hr style='margin:7px 0'>
    """, unsafe_allow_html=True)
 
    st.markdown("</div>", unsafe_allow_html=True)

with main_col:
    if not st.session_state["result_shown"]:
        tab_upload, tab_paste = st.tabs(["Upload .txt File", "Paste Email"])
        with tab_upload:
            uploaded_file = st.file_uploader("Upload your email (.txt file)", type=["txt"])
            
            if uploaded_file and st.button("Submit", key="uploadbtn"):
                st.session_state["email_text"] = uploaded_file.read().decode("utf-8", errors="replace")
                st.session_state["run_analysis"] = True
            
        with tab_paste:
            pasted = st.text_area("Paste email content below", key="pastebox", height=135)
            if st.button("Submit", key="pastebtn"):
                st.session_state["email_text"] = pasted
                st.session_state["run_analysis"] = bool(pasted.strip())

    if st.session_state.get("run_analysis", False) and st.session_state["email_text"].strip():
        st.write("---")
        with st.spinner("Analyzing..."):
            (result, confidence, top_features, sender,
             highlighted, global_phish_terms) = predict_email(st.session_state["email_text"])
        st.session_state["result_shown"] = False
        st.session_state["run_analysis"] = False
        st.session_state["global_phish_terms"] = global_phish_terms
        st.session_state["last_pred_result"] = result
        st.session_state["last_conf"] = confidence

        pred_style = "color:#e04636;font-weight:900;" if result == "phishing" else "color:#18874b;font-weight:900;"

        st.markdown(f"""
        <div class='main-pred' style='font-size:2.8rem; {pred_style}; margin-bottom:0.3em;'>{result.upper()}</div>
        <div style='font-size:1.07em; color:#888; font-weight:500;'>Confidence Score:</div>
        <div style='font-size:2.25rem; font-weight:800; color:#232629; border-radius:8px; padding:0.07em 0.75em; background:#f9f9f9; display:inline-block; margin-bottom:0.7em;'>
            {confidence}%
        </div>
        """, unsafe_allow_html=True)

        st.markdown(
            "<div class='explain-box' style='color:#333; border:1px solid #e3e3e3; padding:2vw; overflow: scroll; height:50vh;width:100%;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);border-radius:8px;'>" +
            "<b>Email</b> <span style='font-weight:500;'>(orange = suspicious, green = legitimate):</span><br><br>" +
            f"<div style='white-space: pre-wrap;line-height:1.65;font-size:1.058em;'>{highlighted}</div><hr style='margin:8px 2px'>" +
            "<b>Top words influencing the decision:</b>" +
            "<ol style='margin-bottom:0'>" +
            ''.join([
                f"<li><span class='orange-mark'>{w}</span> <span class='codeword'>{weight:+.2f}</span></li>" if weight > 0
                else f"<li><span class='green-mark'>{w}</span> <span class='codeword'>{weight:+.2f}</span></li>"
                for w, weight in top_features
            ]) +
            "</ol></div>",
            unsafe_allow_html=True
        )

