# mkdir -p staticfiles_build/static
# mkdir -p main/static
# pip install -r requirements.txt
# python3.9 main/manage.py makemigrations 
python3.9 main/manage.py migrate 
# python3.9 main/manage.py collectstatic --noinput