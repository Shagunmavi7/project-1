# 📧 Spam Email & Phishing Detection

A machine learning project that classifies emails as **Spam / Phishing** or **Legitimate (Ham)** using Natural Language Processing (NLP).

---

## 🚀 Features

- Detects spam and phishing emails from raw text
- Text preprocessing (lowercasing, stopword removal, tokenization, stemming/lemmatization)
- TF-IDF feature extraction
- Trained and compared multiple ML models
- Simple web interface to paste an email and get an instant prediction
- Displays model accuracy, precision, recall and F1-score

---

## 🛠️ Tech Stack

| Area | Tools |
|---|---|
| Language | Python 3 |
| Data handling | Pandas, NumPy |
| NLP | NLTK, TF-IDF (scikit-learn) |
| ML models | Naive Bayes, Logistic Regression, SVM `<edit to match yours>` |
| Web app | `<Flask / Streamlit / FastAPI>` |
| Frontend | HTML, CSS, JavaScript `<edit>` |

---

## 📂 Project Structure

```
spam-phishing-detection/
│
├── data/                 # Dataset (CSV)
├── notebooks/            # Training & EDA notebooks
├── model/                # Saved model and vectorizer (.pkl)
├── templates/            # HTML files
├── static/               # CSS / JS
├── app.py                # Web app entry point
├── train.py              # Model training script
├── requirements.txt
└── README.md
```

---



## ⚙️ How It Works

1. **Load data** – read the email dataset with Pandas
2. **Clean text** – remove punctuation, links, numbers and stopwords
3. **Vectorize** – convert text into numbers using TF-IDF
4. **Train** – fit the classification model on the training split
5. **Evaluate** – check accuracy, precision, recall, F1 and confusion matrix
6. **Predict** – the web app takes new email text and returns the result

---



---

## 💡 Usage

1. Paste the email text into the input box
2. Click **Check**
3. The app shows whether the email is **Spam/Phishing** or **Safe**, with a confidence score

---

## ⚠️ Limitations

- Accuracy depends on the dataset; new phishing styles may not be detected
- Works on text only (does not analyze attachments or full email headers)
- Should not replace professional email security tools

---

## 🔮 Future Improvements

- Detect malicious URLs inside emails
- Use deep learning models (LSTM / BERT)
- Analyze email headers and sender domain
- Browser extension or Gmail integration


## 📄 License

This project is licensed under the MIT License.
