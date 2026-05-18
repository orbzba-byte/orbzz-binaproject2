import streamlit as st
import pandas as pd
import joblib

model = joblib.load('xgb_final_model.pkl')
scaler = joblib.load('scaler_final.pkl')

if hasattr(scaler, 'feature_names_in_'):
    FEATURES_ORDER = list(scaler.feature_names_in_)
else:
    FEATURES_ORDER = [
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
        'Bwd Packet Length Max', 'Bwd Packet Length Mean', 'Max Packet Length',
        'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
        'Average Packet Size', 'Avg Bwd Segment Size', 'Subflow Fwd Bytes',
        'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward'
    ]

CLASSES = [
    'BENIGN', 'Bot', 'DDoS', 'DoS GoldenEye', 'DoS Hulk',
    'DoS Slowhttptest', 'DoS slowloris', 'FTP-Patator',
    'Heartbleed', 'Infiltration', 'PortScan', 'SSH-Patator',
    'Web Attack - Brute Force', 'Web Attack - Sql Injection', 'Web Attack - XSS'
]

ATTACK_DETAILS = {
    'BENIGN': {
        'title': 'Normal Traffic (BENIGN)',
        'indicator': 'Safe and normal internet activity from regular users.'
    },
    'Bot': {
        'title': 'Botnet Attack (Bot)',
        'indicator': 'indicator: Secretly taking control of unprotected computers to make them automatically work together to perform harmful tasks.'
    },
    'DDoS': {
        'title': 'Distributed Denial of Service (DDoS)',
        'indicator': 'indicator: Overwhelming a server by flooding it with traffic from many hacked devices at once to crash the system.'
    },
    'DoS GoldenEye': {
        'title': 'Denial of Service (DoS GoldenEye)',
        'indicator': 'indicator: Overloading specific functions of a website or app to crash the server and block real users from using it.'
    },
    'DoS Hulk': {
        'title': 'Denial of Service (DoS Hulk)',
        'indicator': 'indicator: Flooding a website with a massive number of disguised requests to trick its defense systems and crash the server.'
    },
    'DoS Slowhttptest': {
        'title': 'Denial of Service (DoS Slowhttptest)',
        'indicator': 'indicator: Sneakily keeping connections to a website open for a very long time to fill up its capacity and block others.'
    },
    'DoS slowloris': {
        'title': 'Denial of Service (DoS Slowloris)',
        'indicator': 'indicator: Keeping server connections busy by sending incomplete data very slowly, allowing the attack to hide from basic security systems.'
    },
    'FTP-Patator': {
        'title': 'FTP Brute-Force Attack (FTP-Patator)',
        'indicator': 'indicator: Using a computer program to rapidly guess passwords for file storage accounts to steal sensitive data.'
    },
    'SSH-Patator': {
        'title': 'SSH Brute-Force Attack (SSH-Patator)',
        'indicator': 'indicator: Using fast, automated tools to guess passwords for remote server management to take full control of the system.'
    },
    'Heartbleed': {
        'title': 'Heartbleed Vulnerability Exploitation',
        'indicator': 'indicator: Exploiting a well-known security flaw in old encryption software to peek into the server\'s memory and steal private keys.'
    },
    'Infiltration': {
        'title': 'Network Infiltration',
        'indicator': 'indicator: Tricking an internal computer into running harmful code, creating a permanent secret entrance into the network.'
    },
    'PortScan': {
        'title': 'Port Scanning Reconnaissance (PortScan)',
        'indicator': 'indicator: Checking network systems for open digital doors and active services to map out vulnerabilities for a future attack.'
    },
    'Web Attack - Brute Force': {
        'title': 'Web Content Brute-Force',
        'indicator': 'indicator: Using an automated script to repeatedly guess login information, folders, or web pages to break into a website.'
    },
    'Web Attack - Sql Injection': {
        'title': 'SQL Injection (SQLi)',
        'indicator': 'indicator: Typing harmful database commands into text fields on a website to steal, change, or delete hidden data.'
    },
    'Web Attack - XSS': {
        'title': 'Cross-Site Scripting (XSS)',
        'indicator': 'indicator: Inserting harmful code into a trusted website to hijack user sessions and spy on visitors\' browsers.'
    }
}

st.set_page_config(page_title="Intrusion Detection System", layout="wide")

st.title("Cyber Attack Detection System")

# יצירת טאבים ויזואליים
tab1, tab2 = st.tabs(["- Detection System ", "- About the Project "])


with tab1:

    #  לבחירת שיטת הזנת הנתונים באפליקציה
    input_method = st.radio("Select Traffic Input Stream Mode:", ("Upload File (CSV)", "Manual Feature Input"))

    if input_method == "Manual Feature Input":
        st.markdown("#### Input Network Flow Features")
        inputs = {}
        col1, col2 = st.columns(2)

        # יצירת תיבות קלט דינמיות עבור המשתנים וחלוקתן לשתי עמודות
        for i, f in enumerate(FEATURES_ORDER):
            with col1 if i < (len(FEATURES_ORDER) // 2 + 1) else col2:
                inputs[f] = st.text_input(f"{i+1}. {f}", "0.0")

        if st.button("Predict"):
            try:
                data = pd.DataFrame([[float(inputs[f]) for f in FEATURES_ORDER]], columns=FEATURES_ORDER)
                scaled_data = scaler.transform(data)

                # ביצוע חיזוי באמצעות מודל ה-XGBoost
                pred_idx = int(model.predict(scaled_data)[0])
                predicted_label = CLASSES[pred_idx]

                details = ATTACK_DETAILS.get(predicted_label, {'title': predicted_label, 'indicator': ''})

                if predicted_label == 'BENIGN':
                    st.success(f"Prediction: {details['title']}")
                else:
                    st.error(f"Alert: {details['title']}")
                st.info(details['indicator'])

            except Exception as e:
                st.error(f"Inference Error: {e}")

    elif input_method == "Upload File (CSV)":
        uploaded_file = st.file_uploader("Upload an exported network flow file", type=["csv"])

        if uploaded_file is not None:
            try:
                df = pd.read_csv(uploaded_file)
                # ניקוי כותרות העמודות מרווחים מיותרים כדי למנוע שגיאות התאמה
                df.columns = df.columns.str.strip()

                missing_features = [f for f in FEATURES_ORDER if f not in df.columns]

                if missing_features:
                    st.error(f"Structural Validation Failed. Missing essential parameters: {missing_features}")
                else:
                    if st.button("Predict"):
                        # חילוץ המשתנים בשקט מאחורי הקלעים ונרמולם בסדר המדויק
                        data_to_predict = df[FEATURES_ORDER]
                        scaled_data = scaler.transform(data_to_predict)

                        # הרצת חיזוי מלא על כל שורות הקובץ 
                        predictions = model.predict(scaled_data)
                        predictions_list = [int(x) for x in predictions]

                        # איסוף איומים ייחודיים שעלו מתוך הקובץ (ללא כפילויות)
                        detected_attacks = set()
                        for pred_val in predictions_list:
                            label = CLASSES[pred_val]
                            if label != 'BENIGN':
                                detected_attacks.add(label)

                        # הצגת ממצאי הסיווג
                        if detected_attacks:
                            st.markdown("Cyber Attack Detected!")
                            for attack in detected_attacks:
                                details = ATTACK_DETAILS.get(attack, {'title': attack, 'indicator': ''})
                                st.error(f"Critical Anomaly Identified: {details['title']}")
                                st.info(details['indicator'])
                        else:
                            st.success("Network flow is completely standard.")

            except Exception as e:
                st.error(f"Data Processing Fault: {e}")

with tab2:
    st.markdown("About the Project:")
    st.write("A security model that monitors website traffic to detect and predict cyber attacks.")
    st.info("Using an XGBoost Multi-Class classification model.")
