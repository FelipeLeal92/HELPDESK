# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

This is a comprehensive HelpDesk system built with Python Flask, SQLite, and modern web technologies. The system provides both user and administrative interfaces for ticket management, with real-time notifications and file attachment support.

## Quick Start Commands

### Database Management
```bash
# Initialize/reset database (creates tables and sample data)
python database.py

# Add additional ticket types
python add_ticket_types.py
```

### Development
```bash
# Start the development server
python app.py
# Server runs on http://localhost:5000

# Run in different port if needed
# Edit app.py line 960: app.run(host='0.0.0.0', port=5001, debug=True)
```

### Testing Access
The system comes with pre-configured test users:
- **Admin**: admin@example.com / admin
- **Regular User**: joao@example.com / user123
- **Manager**: manager@example.com / manager123

## Architecture Overview

### Core Structure
The application follows a traditional Flask MVC pattern:

- **`app.py`**: Main Flask application with all routes and business logic
- **`database.py`**: Database schema definition and initialization
- **`templates/`**: HTML templates for UI
- **`uploads/`**: File storage for ticket attachments
- **`helpdesk.db`**: SQLite database file

### Key Architectural Patterns

#### Role-Based Access Control
The system implements three user roles:
- **`user`**: Can create and view own tickets
- **`manager`**: Has admin privileges for ticket management
- **`admin`**: Full system access including user management

Access control is implemented via session checks in routes:
```python
if session.get('user_role') not in ['admin', 'manager']:
    return jsonify({'error': 'Unauthorized'}), 401
```

#### Session Management
- Uses Flask sessions with 7-day persistence
- "Remember me" functionality with secure cookies
- Automatic role-based redirects after login

#### Real-time Notifications
Implements Server-Sent Events (SSE) for real-time updates:
- **Event Hub**: In-memory queue system (`user_event_queues`)
- **Notification Types**: Email, SMS (placeholder), and push via SSE
- **User Preferences**: Configurable notification preferences per user

### Database Architecture

#### Core Tables
- **`users`**: User accounts with role-based permissions
- **`tickets`**: Main ticket entity with status tracking
- **`ticket_types`**: Configurable ticket categories
- **`ticket_statuses`**: Configurable status options with colors
- **`ticket_responses`**: Threaded conversations on tickets
- **`attachments`**: File uploads linked to tickets/responses
- **`logs`**: System activity logging
- **`settings`**: Key-value configuration storage

#### Important Relationships
- Tickets belong to users (user_id foreign key)
- Tickets can be assigned to staff (assigned_to foreign key)
- Responses create conversation threads
- Attachments can belong to tickets or specific responses

### Frontend Architecture

#### Template Structure
- **`index.html`**: Login page with company branding
- **`dashboard-user.html`**: User interface (tickets, profile, help center)
- **`dashboard-admin.html`**: Administrative interface (management, reports)
- **`recover.html`**: Password recovery form

#### Technology Stack
- **TailwindCSS**: Utility-first CSS framework
- **Material Symbols**: Google's icon system
- **Vanilla JavaScript**: No framework dependencies
- **AJAX**: Async communication with Flask API

## API Structure

### Authentication Routes
- `POST /login` - User authentication
- `GET /logout` - Session termination
- `POST /recover` - Password reset

### User API Routes
- `GET /api/tickets` - List user tickets (admin sees all)
- `POST /api/tickets` - Create new ticket (supports file uploads)
- `GET /api/tickets/<id>` - Get ticket details with attachments
- `GET /api/tickets/<id>/responses` - Get ticket conversation
- `POST /api/tickets/<id>/responses` - Add response to ticket

### Admin API Routes
- `GET /api/admin/stats` - Dashboard statistics
- `GET /api/admin/tickets/recent` - Recent tickets overview
- `GET /api/admin/users` - User management listing
- `POST /api/admin/users` - Create new user
- `PUT /api/admin/users/<id>` - Update user details
- `DELETE /api/admin/users/<id>` - Remove user
- `PUT /api/admin/tickets/<id>/status` - Update ticket status

### Configuration API Routes
- `GET/PUT /api/admin/settings` - System configuration
- `GET/PUT /api/help-center` - Help center content management
- `GET/POST/PUT/DELETE /api/ticket-types` - Ticket category management
- `GET/POST/PUT/DELETE /api/ticket-statuses` - Status management

## File Upload System

### Configuration
- **Storage Location**: `uploads/` directory
- **Allowed Extensions**: jpg, jpeg, png, pdf, xls, xlsx, csv
- **Size Limit**: 10MB per file
- **Naming Convention**: `{ticket_id}_{random_hex}_{original_filename}`

### Security Measures
- Filename sanitization using `secure_filename()`
- Extension validation
- File size enforcement
- Unique naming to prevent conflicts

## Development Guidelines

### Adding New Features
1. **Database Changes**: Update `database.py` schema and add migration logic to `ensure_schema_and_password_hash()`
2. **API Routes**: Add new routes in `app.py` following existing patterns
3. **Frontend**: Update relevant templates and add JavaScript handlers
4. **Permissions**: Ensure proper role-based access control

### Password Security
The system currently uses SHA-256 hashing. The `ensure_schema_and_password_hash()` function handles migration from plaintext to hashed passwords automatically.

### Configuration Management
System settings are stored in the `settings` table as key-value pairs. Use the settings API endpoints for configuration management.

### Logging and Monitoring
- All significant actions are logged to the `logs` table
- User activity is tracked with `log_event()` function
- Real-time notifications are sent via `notify_user_ticket_update()`

## Common Development Tasks

### Running Tests
The system includes test users and sample data for development. Access the login page to see available test accounts.

### Adding New Ticket Types
Use the admin interface or run `add_ticket_types.py` to add new categories. Categories can be managed via the `/api/ticket-types` endpoints.

### Modifying User Roles
Update the user's `role` field in the database. Valid roles are: `user`, `manager`, `admin`.

### Email Configuration
Update the `send_email()` function in `app.py` with proper SMTP settings for production use. Currently it's a placeholder that prints to console.

### File Storage
Uploaded files are stored in the `uploads/` directory. For production, consider implementing cloud storage integration.

## Production Considerations

### Security
- Change the `secret_key` from the default value
- Implement proper HTTPS configuration
- Consider implementing bcrypt for password hashing
- Review file upload security measures

### Database
- Consider migrating from SQLite to PostgreSQL for production
- Implement proper database backup procedures
- Add database connection pooling for high traffic

### Performance
- Implement caching for frequently accessed data
- Consider CDN integration for file uploads
- Add database indexing for frequently queried fields

### Monitoring
- Implement proper error logging
- Add performance monitoring
- Set up alerting for system issues
