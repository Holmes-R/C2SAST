from nicegui import ui, app
import requests
import asyncio

API_BASE = "http://localhost:5000/api"

# ====================== STATE ======================
class AppState:
    username: str = ''
    password: str = ''
    token: str = ''

state = AppState()

# ====================== FUNCTIONS ======================
def login():
    if not state.username.strip():
        ui.notify('Please enter a username', type='negative')
        return

    try:
        resp = requests.post(
            f"{API_BASE}/register", 
            json={"username": state.username.strip(), "password": state.password.strip()}
        )
        
        if resp.status_code == 200:
            token = resp.json().get('token')
            if token:
                state.token = token
                app.storage.user['token'] = token
                ui.notify('✅ Login successful!', type='positive')
                show_analyzer()
            else:
                ui.notify('No token received', type='negative')
        else:
            ui.notify(f'Login failed: {resp.status_code}', type='negative')
    except Exception as e:
        ui.notify(f'Connection error: {e}', type='negative')


async def upload_handler(e):
    if not e.file:
        return
    try:
        file_info = e.file
        content = await file_info.read()
        ui.notify(f'File received: {file_info.name} ({len(content)} bytes)', type='positive')
        
        # Temporary debug call
        resp = requests.post(
            f"{API_BASE}/analyze",
            files={'file': (file_info.name, content)},
            headers={'Authorization': f'Bearer {state.token}'}
        )
        ui.notify(f'Status: {resp.status_code}', type='info')
        if resp.status_code != 200:
            ui.notify(resp.text[:300], type='negative')  # show error message
        else:
            display_report(resp.json())
    except Exception as ex:
        ui.notify(f'Error: {ex}', type='negative')


def show_analyzer():
    main_content.clear()
    
    with main_content:
        ui.label('C2SAST - C/C++ Static Analyzer').classes('text-h4 mb-6')
        
        ui.upload(
            label='Upload .c / .cpp / .h file',
            multiple=False,
            on_upload=upload_handler,   # ← now async
            auto_upload=True
        ).props('accept=.c,.cpp,.h').classes('w-full max-w-md')


async def download_pdf(result):
    try:
        resp = requests.post(
            f"{API_BASE}/export-pdf",
            json=result,
            headers={'Authorization': f'Bearer {state.token}'}
        )
        if resp.status_code == 200:
            ui.download(resp.content, filename=f"{result.get('filename')}.pdf")
            ui.notify('✅ PDF downloaded!', type='positive')
        else:
            ui.notify(f'Failed to export PDF: {resp.status_code}', type='negative')
    except Exception as ex:
        ui.notify(f'Error: {ex}', type='negative')

def display_report(result):
    main_content.clear()
    
    with main_content:
        ui.button('← Back to Upload', on_click=show_analyzer).classes('mb-4')
        
        ui.label(f"Report: {result.get('filename', 'Unknown file')}").classes('text-h5 mb-4')
        
        # Download PDF button
        ui.button('Download PDF Report', icon='download', on_click=lambda: download_pdf(result)).classes('mb-4')
        
        vulnerabilities = result.get('vulnerabilities', [])
        if not vulnerabilities:
            ui.label('✅ No vulnerabilities found!').classes('text-green-600 text-lg')
            return
            
        # Terminal-style summary table
        columns = [
            {'name': 'line', 'label': 'Line', 'field': 'line', 'sortable': True, 'align': 'left'},
            {'name': 'severity', 'label': 'Severity', 'field': 'severity', 'sortable': True, 'align': 'left'},
            {'name': 'name', 'label': 'Vulnerability', 'field': 'name', 'sortable': True, 'align': 'left'},
            {'name': 'cwe', 'label': 'CWE', 'field': 'cwe', 'align': 'left'},
        ]
        rows = [{'line': v.get('line'), 'severity': v.get('severity'), 'name': v.get('name'), 'cwe': v.get('cwe')} for v in vulnerabilities]
        ui.table(columns=columns, rows=rows, row_key='name').classes('w-full mb-8')
        
        ui.label('Detailed Explanations:').classes('text-h6 mb-2')
        
        for vuln in vulnerabilities:
            with ui.card().classes('w-full my-4 p-4'):
                ui.label(vuln.get('name', 'Unknown Vulnerability')).classes('text-h6 text-red-600')
                ui.label(f"CWE: {vuln.get('cwe', 'N/A')} | Severity: {vuln.get('severity', 'N/A')}").classes('text-sm')
                
                ui.label(f"Line {vuln.get('line', '?')}: {vuln.get('snippet', '')}").classes('font-mono bg-gray-100 p-2 rounded text-sm my-2')
                
                ui.markdown(f"**Why dangerous?** {vuln.get('explanation', '')}")
                
                with ui.expansion('Mitigation', value=True).classes('w-full'):
                    ui.markdown(vuln.get('mitigation', 'No mitigation provided.'))
                
                with ui.expansion('Secure Code Example', value=True).classes('w-full'):
                    ui.code(vuln.get('secure_code', '// No example provided'), language='cpp')


# ====================== UI ======================
with ui.header().classes('justify-between items-center'):
    ui.label('C2SAST').classes('text-h6')
    ui.button('Logout', on_click=lambda: (setattr(state, 'token', ''), app.storage.user.clear(), show_login())) \
        .bind_visibility_from(state, 'token')

main_content = ui.column().classes('w-full items-center p-6')

def show_login():
    main_content.clear()
    with main_content:
        with ui.card().classes('w-full max-w-md p-6 shadow-lg rounded-xl'):
            ui.label('Welcome to C2SAST').classes('text-h4 font-bold text-center mb-6')
            
            ui.input(
                label='Username',
                placeholder='Enter username',
            ).bind_value(state, 'username').props('outlined').classes('w-full')
            
            ui.input(
                label='Password',
                password=True,
                password_toggle_button=True,
            ).bind_value(state, 'password').props('outlined').classes('w-full mt-4')
            
            with ui.row().classes('w-full mt-6 gap-4'):
                ui.button('Login', on_click=login).props('color=primary').classes('flex-grow')
                ui.button('Sign Up', on_click=login).props('color=secondary').classes('flex-grow')

# Start with login
show_login()

# Run the app
ui.run(
    title='C2SAST - Vuln AI',
    port=8080,
    reload=True,
    storage_secret='super-secret-key-change-in-production'
)