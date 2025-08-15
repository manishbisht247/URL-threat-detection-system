import streamlit as st
import pandas as pd
import joblib
import features_extract # your existing extractor

# ==============================
# Load model and metadata
# ==============================
@st.cache_resource
def load_model():
    return joblib.load("model.pkl")

model = load_model()

# Determine which class label is phishing/malicious
classes = model.classes_
minority_class = min(classes)  # adjust if 1=phishing in your dataset
minority_label_name = "Malicious" if minority_class == 0 else "Legit"

# ==============================
# Streamlit Page Config
# ==============================
st.set_page_config(
    page_title="URL THREAT DETECTOR",
    page_icon="🌐",
    layout="centered",
)

st.markdown(
    """
    <style>
        .result-box {
            padding: 20px;
            border-radius: 10px;
            font-size: 1.2rem;
            text-align: center;
            font-weight: bold;
        }
    </style>
    """,
    unsafe_allow_html=True
)

# ==============================
# Title & Description
# ==============================
st.title("🌐 URL Threat Detection Dashboard")
st.write("Enter a URL to check if it's **Legit** or **Malicious** using our trained Random Forest model.")

# ==============================
# Input URL
# ==============================
url_input = st.text_input("🔗 Enter URL here:", "")

if st.button("Check URL"):
    if url_input.strip() == "":
        st.warning("Please enter a valid URL.")
    else:
        try:
            # Extract features
            features = features_extract.extract_essential_features(url_input)
            X_new = pd.DataFrame([features])

            # Predict
            pred = model.predict(X_new)[0]
            pred_proba = model.predict_proba(X_new)[0]

            # Map prediction to readable label
            label_map = {0: "Malicious", 1: "Legit"}
            prediction_text = label_map.get(pred, "Unknown")

            # Probability of being predicted class
            pred_class_index = list(model.classes_).index(pred)
            probability_percent = round(pred_proba[pred_class_index] * 100, 2)

            # Display result with colored box
            if prediction_text == "Malicious":
                st.markdown(
                    f"<div class='result-box' style='background-color:#ffcccc;color:#800000;'>"
                    f"🚨 Prediction: {prediction_text} ({probability_percent}%)"
                    f"</div>", unsafe_allow_html=True)
            else:
                st.markdown(
                    f"<div class='result-box' style='background-color:#ccffcc;color:#006600;'>"
                    f"✅ Prediction: {prediction_text} ({probability_percent}%)"
                    f"</div>", unsafe_allow_html=True)

        except Exception as e:
            st.error(f"Error: {str(e)}")
