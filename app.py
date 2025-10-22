from flask import Flask, request, jsonify, render_template
from cipher_tools.vigenere import vigenere_break
from cipher_tools.caesar import caesar_break
from cipher_tools.permutation import permutation_break
from cipher_tools.columnar_transposition import columnar_break
from cipher_tools.frequency_analyser import analyse
from cipher_tools.affine import affine_break
from cipher_tools.amsco import amsco_break
from cipher_tools.railfence import railfence_break
app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    amsco=False
    if request.method == "POST":
        text = request.form.get("text", "")
        cipher_type = request.form.get("cipher_type", "vigenere").lower()

        if cipher_type == "caesar":
            key, plaintext = caesar_break(text)
        elif cipher_type== "vigenere":  # default to vigenere
            key, plaintext = vigenere_break(text)
        elif cipher_type == "permutation":
            key, plaintext = permutation_break(text)
        elif cipher_type == "columnar":
            key, plaintext = columnar_break(text)
        elif cipher_type == "affine":
            key,plaintext = affine_break(text)
        elif cipher_type == "amsco":
            key,plaintext = amsco_break(text)
        elif cipher_type == "railfence":
            key,plaintext = railfence_break(text)
            
        

        return jsonify({"key": key, "text": plaintext})

    return render_template("index.html")

@app.route("/frequency", methods=["GET", "POST"])
def frequency():
    if request.method == "POST":
        text = request.form.get("text", "")
        trigrams, bigrams, unigrams, cipher_type = analyse(text)
    # Format unigrams nicely
        unigrams_str = ", ".join([f"{letter}: {count}" for letter, count in unigrams])
        # Format results as strings
        result_text = f"Common trigrams: {trigrams}\n"
        result_text += f"\nCommon bigrams: {bigrams}\n"
        result_text += f"\nLetter frequencies: {unigrams_str}\n"
        result_text += f"\nLikely cipher type: {cipher_type}"

        return jsonify({"text": result_text})

    return render_template("frequency.html")
@app.route("/sitemap.xml")
def sitemap():
    return send_from_directory('.', 'sitemap.xml', mimetype='application/xml')
@app.route("/google-site-verification=yL9ZyE9FIdPmgn447gFEGkiwtHNKWodpHC43zVLSMAI.html")
def google_verification():
    return send_from_directory('.', 'google-site-verification=yL9ZyE9FIdPmgn447gFEGkiwtHNKWodpHC43zVLSMAI.html')
if __name__ == "__main__":
    app.run()



