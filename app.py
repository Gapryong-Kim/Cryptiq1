from flask import Flask, request, jsonify, render_template
from cipher_tools.vigenere import vigenere_break
from cipher_tools.caesar import caesar_break
from cipher_tools.permutation import permutation_break
from cipher_tools.columnar_transposition import columnar_break
from cipher_tools.frequency_analyser import analyse
from cipher_tools.affine import affine_break
from cipher_tools.amsco import amsco_break
from cipher_tools.railfence import railfence_break
from utility.polybius_square import polybius_standardize
from utility.unique import unique
app = Flask(__name__)

# ------------------- Main Cipher Breaker -------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        text = request.form.get("text", "")
        cipher_type = request.form.get("cipher_type", "vigenere").lower()

        if cipher_type == "caesar":
            key, plaintext = caesar_break(text)
        elif cipher_type == "vigenere":
            key, plaintext = vigenere_break(text)
        elif cipher_type == "permutation":
            key, plaintext = permutation_break(text)
        elif cipher_type == "columnar":
            key, plaintext = columnar_break(text)
        elif cipher_type == "affine":
            key, plaintext = affine_break(text)
        elif cipher_type == "amsco":
            key, plaintext = amsco_break(text)
        elif cipher_type == "railfence":
            key, plaintext = railfence_break(text)
        else:
            key, plaintext = None, text

        return jsonify({"key": key, "text": plaintext})

    return render_template("index.html")

# ------------------- Tools Page -------------------
@app.route("/tools", methods=["GET"])
def tools_page():
    return render_template("tools.html")

# ------------------- Tools API -------------------
@app.route("/tools/run", methods=["POST"])
def tools_run():
    text = request.form.get("text", "")
    tool_type = request.form.get("tool_type", "").lower()

    if tool_type == "frequency":
        trigrams, bigrams, unigrams, cipher_type = analyse(text)
        unigrams_str = ", ".join([f"{letter}: {count}" for letter, count in unigrams])
        result_text = f"Common trigrams: {trigrams}\n"
        result_text += f"\nCommon bigrams: {bigrams}\n"
        result_text += f"\nLetter frequencies: {unigrams_str}\n"
        result_text += f"\nLikely cipher type: {cipher_type}"

    elif tool_type == "polybius":
        initial_text = polybius_standardize(text)
        trigrams, bigrams, unigrams, cipher_type = analyse(initial_text)
        unigrams_str = ", ".join([f"{letter}: {count}" for letter, count in unigrams])
        result_text = initial_text + "\n"
        result_text += f"Common trigrams: {trigrams}\n"
        result_text += f"Common bigrams: {bigrams}\n"
        result_text += f"Letter frequencies: {unigrams_str}\n"
    elif tool_type == "unique":
        result_text='\n'.join(i for i in unique(text))

    elif tool_type == "substitution":
        # For substitution, frontend handles mapping; just return the raw text
        result_text = text.upper()

    else:
        result_text = "Unknown tool selected."

    return jsonify({"text": result_text})

# ------------------- Frequency Analysis for Substitution -------------------

if __name__ == "__main__":
    app.run(debug=True)
