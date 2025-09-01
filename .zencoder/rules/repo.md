# Repo Profile: HelpDesk_LogTudo

- **Stack**: Python (Flask), SQLite, Tailwind CSS (via CDN), Vanilla JS
- **App entry**: app.py (Flask application and routes)
- **Templates**: Templates/ (dashboard-admin.html, dashboard-user.html, index.html, recover.html)
- **Static uploads**: uploads/ (served via /uploads/<filename>)
- **Database file**: helpdesk.db (SQLite)

## Key Flask Routes
- **/**: login/index
- **/login**: POST login
- **/logout**: clear session + cookie
- **/recover**: password reset form
- **/admin/dashboard**: admin view (dashboard-admin.html)
- **/user/dashboard**: user view (dashboard-user.html)
- **/uploads/<path:filename>**: serves uploaded files from uploads/

### Tickets (User scope)
- GET **/api/tickets**: list tickets for logged user; if admin, list all with user name
- GET **/api/tickets/<id>**: get ticket details with attachments (authZ: admin or owner)
- POST **/api/tickets**: create ticket
  - Accepts multipart/form-data with field names: type, priority, subject, description, attachments (multiple); validates extensions and size (10MB). Fallback JSON accepted without attachments.

### Admin API
- GET **/api/admin/stats**: { total, open, resolved }
- GET **/api/admin/tickets/recent**: last 10 tickets (join users)
- GET **/api/admin/users**: list users
- POST/PUT/DELETE **/api/admin/users**: CRUD

## Uploads
- **Folder**: uploads/
- **Allowed**: jpg, jpeg, png, pdf, xls, xlsx, csv
- **Limit**: 10MB por arquivo
- **Generated name**: <ticketId>_<hex>_<original>

## Frontend Behavior
- User dashboard:
  - New ticket form sends FormData (multipart) with attachments.
  - Dropzone triggers file input; shows selected names.
  - View button opens modal with details + attachments list (links use /uploads/ paths).
  - Modal container uses Tailwind flex + items-center + justify-center to stay centered.

- Admin dashboard:
  - Recent tickets table includes a "view" action that opens ticket modal with same details and attachments.

## Security Notes
- Session required for all ticket API calls.
- Authorization enforced on GET /api/tickets/<id> (admin or owner).
- Passwords currently compared in plaintext in login and updated in recover; consider hashing with bcrypt.

## Local Run
- Ensure virtualenv is active (.venv)
- Run: `python app.py` (if an app.run is present; else use WSGI/Flask CLI)
- Database: helpdesk.db must contain tables users, tickets, attachments.

## Known UI Considerations
- Navigation functions updated to not rely on global event when called programmatically.
- Modals use `hidden flex` toggling to ensure centering.