from flask import Flask, request, render_template, send_file
from stegano import lsb
import os
from PIL import Image

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
RESULT_FOLDER = "results"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

# Allowed extensions
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'gif'}
ALLOWED_TEXT_EXTENSIONS = {'txt'}

def allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def allowed_text(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_TEXT_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/hide', methods=['POST'])
def hide_text():
    if 'image' not in request.files or 'text' not in request.files:
        return render_template('index.html', message="Both image and text file are required!")
    
    image = request.files['image']
    text_file = request.files['text']
    
    if image.filename == '' or text_file.filename == '':
        return render_template('index.html', message="No selected file!")
    
    if not (allowed_image(image.filename) and allowed_text(text_file.filename)):
        return render_template('index.html', message="Invalid file types! Image must be PNG/JPG and text must be TXT.")
    
    try:
        # Save original image
        image_path = os.path.join(UPLOAD_FOLDER, image.filename)
        image.save(image_path)
        
        # Read text file
        text = text_file.read().decode('utf-8')
        
        # Hide text inside image
        stego_image_path = os.path.join(RESULT_FOLDER, "stego_" + image.filename)
        secret_image = lsb.hide(image_path, text)
        
        # Save stego image
        secret_image.save(stego_image_path)
        
        # Clean up original upload
        os.remove(image_path)
        
        return render_template('index.html', 
                             message="Text hidden successfully!", 
                             stego_image=stego_image_path, 
                             download_link=stego_image_path)
    
    except Exception as e:
        return render_template('index.html', message=f"Error occurred: {str(e)}")

@app.route('/reveal', methods=['POST'])
def reveal_text():
    if 'stego_image' not in request.files:
        return render_template('index.html', message="No file uploaded!")
    
    image = request.files['stego_image']
    
    if image.filename == '':
        return render_template('index.html', message="No selected file!")
    
    if not allowed_image(image.filename):
        return render_template('index.html', message="Invalid file type! Only image files are allowed.")
    
    try:
        # Save the uploaded stego image
        image_path = os.path.join(UPLOAD_FOLDER, image.filename)
        image.save(image_path)
        
        # Extract hidden text
        hidden_text = lsb.reveal(image_path)
        
        # Clean up the uploaded file
        os.remove(image_path)
        
        if hidden_text:
            return render_template('index.html', 
                                 message="Hidden Text Revealed:", 
                                 hidden_text=hidden_text)
        else:
            return render_template('index.html', 
                                 message="No hidden text found in the image.")
    
    except Exception as e:
        return render_template('index.html', 
                             message=f"Error: Could not extract text. {str(e)}")

@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(RESULT_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return render_template('index.html', message="File not found!")

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
