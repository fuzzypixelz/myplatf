# myplatf

## Usage

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
OPENAI_API_KEY=<your-api-key> python3 app.py
```

## Database migration

```bash
flask db migrate -m "<table_name> table"
flask db upgrade
```
