from flask import Flask, request, jsonify
import os
import tempfile
import PyPDF2
import openai
from dotenv import load_dotenv
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "*", "supports_credentials": True}})

# OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")

def extract_text_from_pdf(pdf_file):
    text = ""
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            pdf_file.save(temp_file.name)
            
            # process pages one by one to reduce memory usage
            with open(temp_file.name, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                # limit to 2 pages to reduce memory usage
                max_pages = min(2, len(pdf_reader.pages))
                
                for page_num in range(max_pages):
                    # extract text and release memory
                    page = pdf_reader.pages[page_num]
                    page_text = page.extract_text()
                    text += page_text
                    # force memory release
                    page = None
                    page_text = None
    finally:
        # temporary file cleanup
        try:
            os.unlink(temp_file.name)
        except:
            pass
    
    return text[:8000] if text else "" # first 8000 characters

def analyze_vulnerabilities(pdf_text):
    try:
        prompt = f"""
You are a cybersecurity expert analyzing web vulnerabilities.

Analyze this security report and identify the main vulnerabilities. For each vulnerability:
1. Name the vulnerability clearly
2. Rate its severity (Critical/High/Medium/Low)
3. Provide a detailed description of what the vulnerability is and its security implications
4. Include one helpful resources about this vulnerability

FORMAT YOUR RESPONSE IN HTML using this structure:

<div class="vulnerability">
    <h3>[Vulnerability Name]</h3>
    <p><strong>🚨 Severity:</strong> [Critical/High/Medium/Low]</p>
    <p><strong>💥 Description:</strong> [Detailed explanation of what this vulnerability is, how it works, and why it's dangerous]</p>
    <p><strong>📚 Resources:</strong></p>
    <ul class="resources">
        <li><a href="[URL to resource about this vulnerability]" target="_blank">[Name of resource]</a></li>
    </ul>
</div>

[Repeat for each vulnerability]

{pdf_text}
"""
        
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",  # using a less powerful model to reduce memory costs
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specialized in identifying and remediating vulnerabilities."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=3000 
        )
        
        return {
            "success": True,
            "analysis": response.choices[0].message.content
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@app.route('/api/upload-pdf', methods=['POST'])
def upload_pdf():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file has been uploaded"}), 400
    
    pdf_file = request.files['file']
    
    if not pdf_file.filename.endswith('.pdf'):
        return jsonify({"success": False, "error": "The file must be in PDF format"}), 400

    # 2MB limit    
    if pdf_file.content_length and pdf_file.content_length > 2 * 1024 * 1024:
        return jsonify({"success": False, "error": "File size exceeds 2MB limit"}), 413
    
    try:
        pdf_text = extract_text_from_pdf(pdf_file)
        
        if not pdf_text:
            return jsonify({"success": False, "error": "Text could not be extracted from the PDF"}), 400
        
        result = analyze_vulnerabilities(pdf_text)
        return jsonify(result)
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error processing PDF: {error_details}")
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5200)