CREATE TABLE users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  phone TEXT,
                  is_admin INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, email_updates INTEGER DEFAULT 1, sms_urgent INTEGER DEFAULT 0, push_realtime INTEGER DEFAULT 1, role TEXT DEFAULT 'user');
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE ticket_types
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  description TEXT,
                  active INTEGER DEFAULT 1);
CREATE TABLE ticket_statuses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  color TEXT DEFAULT '#gray',
                  active INTEGER DEFAULT 1);
CREATE TABLE tickets
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  type TEXT NOT NULL,
                  priority TEXT NOT NULL,
                  subject TEXT,
                  description TEXT NOT NULL,
                  status TEXT DEFAULT 'Aberto',
                  assigned_to INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  closed_at TIMESTAMP, closed_by INTEGER,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (assigned_to) REFERENCES users (id));
CREATE TABLE ticket_responses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ticket_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  message TEXT NOT NULL,
                  is_internal INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (ticket_id) REFERENCES tickets (id),
                  FOREIGN KEY (user_id) REFERENCES users (id));
CREATE TABLE attachments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ticket_id INTEGER,
                  response_id INTEGER,
                  filename TEXT NOT NULL,
                  filepath TEXT NOT NULL,
                  filesize INTEGER,
                  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (ticket_id) REFERENCES tickets (id),
                  FOREIGN KEY (response_id) REFERENCES ticket_responses (id));
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  ticket_id INTEGER,
                  message TEXT NOT NULL,
                  is_read INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (ticket_id) REFERENCES tickets (id));
