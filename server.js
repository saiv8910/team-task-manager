const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || process.env.DATABASE_PUBLIC_URL,
  ssl: {
    rejectUnauthorized: false
  }
});
// Initialize database tables
async function initDB() {
  try {
    await pool.query(`
      CREATE EXTENSION IF NOT EXISTS "pgcrypto";

      CREATE TABLE IF NOT EXISTS users (
        id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS projects (
        id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        owner_id UUID REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS project_members (
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
        PRIMARY KEY (user_id, project_id)
      );

      CREATE TABLE IF NOT EXISTS tasks (
        id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'pending',
        due_date DATE,
        project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
        assigned_to UUID REFERENCES users(id) ON DELETE SET NULL
      );
    `);

    console.log('Database tables ready');
  } catch (err) {
    console.error('Database init error:', err.message);
  }
}

initDB();
// initDB();

// Middleware to verify JWT
function auth(req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ========== AUTH ROUTES ==========

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const hashed = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashed]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);

    res.json({ token, user });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== PROJECT ROUTES ==========

app.get('/api/projects', auth, async (req, res) => {
  const result = await pool.query(
    `SELECT p.* FROM projects p
     LEFT JOIN project_members pm ON p.id = pm.project_id
     WHERE p.owner_id = $1 OR pm.user_id = $1`,
    [req.userId]
  );

  res.json(result.rows);
});

app.post('/api/projects', auth, async (req, res) => {
  const { name, description } = req.body;

  const result = await pool.query(
    'INSERT INTO projects (name, description, owner_id) VALUES ($1, $2, $3) RETURNING *',
    [name, description, req.userId]
  );

  await pool.query(
    'INSERT INTO project_members (user_id, project_id) VALUES ($1, $2)',
    [req.userId, result.rows[0].id]
  );

  res.status(201).json(result.rows[0]);
});

app.get('/api/projects/:id', auth, async (req, res) => {
  const project = await pool.query(
    'SELECT * FROM projects WHERE id = $1',
    [req.params.id]
  );

  if (project.rows.length === 0) {
    return res.status(404).json({ error: 'Not found' });
  }

  const members = await pool.query(
    `SELECT u.id, u.name, u.email
     FROM users u
     JOIN project_members pm ON u.id = pm.user_id
     WHERE pm.project_id = $1`,
    [req.params.id]
  );

  const tasks = await pool.query(
    `SELECT t.*, u.name as assignee_name
     FROM tasks t
     LEFT JOIN users u ON t.assigned_to = u.id
     WHERE t.project_id = $1`,
    [req.params.id]
  );

  res.json({
    project: project.rows[0],
    members: members.rows,
    tasks: tasks.rows
  });
});

app.post('/api/projects/:id/members', auth, async (req, res) => {
  const { email } = req.body;

  const user = await pool.query(
    'SELECT id FROM users WHERE email = $1',
    [email]
  );

  if (user.rows.length === 0) {
    return res.status(404).json({ error: 'User not found' });
  }

  await pool.query(
    `INSERT INTO project_members (user_id, project_id)
     VALUES ($1, $2)
     ON CONFLICT DO NOTHING`,
    [user.rows[0].id, req.params.id]
  );

  res.json({ message: 'Member added' });
});

// ========== TASK ROUTES ==========

app.post('/api/tasks', auth, async (req, res) => {
  const { title, description, due_date, project_id, assigned_to } = req.body;

  const result = await pool.query(
    `INSERT INTO tasks
     (title, description, due_date, project_id, assigned_to)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [title, description, due_date, project_id, assigned_to]
  );

  res.status(201).json(result.rows[0]);
});

app.patch('/api/tasks/:id/status', auth, async (req, res) => {
  const { status } = req.body;

  await pool.query(
    'UPDATE tasks SET status = $1 WHERE id = $2',
    [status, req.params.id]
  );

  res.json({ message: 'Updated' });
});

app.delete('/api/tasks/:id', auth, async (req, res) => {
  await pool.query(
    'DELETE FROM tasks WHERE id = $1',
    [req.params.id]
  );

  res.json({ message: 'Deleted' });
});

// ========== DASHBOARD ==========

app.get('/api/dashboard', auth, async (req, res) => {
  const tasks = await pool.query(
    `SELECT t.*, p.name as project_name
     FROM tasks t
     JOIN projects p ON t.project_id = p.id
     WHERE t.assigned_to = $1`,
    [req.userId]
  );

  const stats = {
    total: tasks.rows.length,
    pending: tasks.rows.filter(t => t.status === 'pending').length,
    in_progress: tasks.rows.filter(t => t.status === 'in_progress').length,
    completed: tasks.rows.filter(t => t.status === 'completed').length,
    overdue: tasks.rows.filter(
      t =>
        t.due_date &&
        new Date(t.due_date) < new Date() &&
        t.status !== 'completed'
    ).length
  };

  res.json({
    tasks: tasks.rows,
    stats
  });
});

// Serve a simple HTML frontend
app.get('*', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Task Manager</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body class="bg-gray-100">
  <div id="root"></div>

  <script>
    const API_URL = '/api';
    let token = localStorage.getItem('token');

    function fetchJSON(url, options = {}) {
      return fetch(url, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': 'Bearer ' + token } : {})
        }
      }).then(r => r.json());
    }

    async function load() {
      if (!token) {
        renderAuth();
        return;
      }

      const user = JSON.parse(localStorage.getItem('user') || '{}');
      const dashboard = await fetchJSON(API_URL + '/dashboard');
      const projects = await fetchJSON(API_URL + '/projects');

      renderApp(user, dashboard, projects);
    }

    function renderAuth() {
      document.getElementById('root').innerHTML = \`
        <div class="max-w-md mx-auto mt-20 bg-white p-8 rounded shadow">
          <h2 class="text-2xl font-bold mb-6">Task Manager</h2>

          <div id="auth-form">
            <input id="name" type="text" placeholder="Name" class="w-full p-2 border rounded mb-2" style="display:none">
            <input id="email" type="email" placeholder="Email" class="w-full p-2 border rounded mb-2">
            <input id="password" type="password" placeholder="Password" class="w-full p-2 border rounded mb-4">

            <button onclick="login()" class="w-full bg-blue-600 text-white py-2 rounded">Login</button>

            <p class="mt-2 text-center">
              <a href="#" onclick="showSignup(); return false" class="text-blue-600">Create account</a>
            </p>
          </div>
        </div>
      \`;
    }

    window.showSignup = () => {
      document.getElementById('name').style.display = 'block';
      document.querySelector('button').innerHTML = 'Sign Up';
      document.querySelector('button').onclick = signup;
    };

    window.login = async () => {
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;

      const res = await fetch(API_URL + '/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await res.json();

      if (data.token) {
        token = data.token;
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(data.user));
        load();
      } else {
        alert('Login failed');
      }
    };

    window.signup = async () => {
      const name = document.getElementById('name').value;
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;

      const res = await fetch(API_URL + '/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password })
      });

      const data = await res.json();

      if (data.token) {
        token = data.token;
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(data.user));
        load();
      } else {
        alert('Signup failed');
      }
    };

    window.logout = () => {
      localStorage.clear();
      token = null;
      load();
    };

    window.createProject = async () => {
      const name = prompt('Project name:');

      if (!name) return;

      await fetch(API_URL + '/projects', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ name })
      });

      load();
    };

    window.addMember = async (projectId) => {
      const email = prompt('Member email:');

      if (!email) return;

      await fetch(API_URL + '/projects/' + projectId + '/members', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });

      alert('Member added (if exists)');
      load();
    };

    window.createTask = async (projectId) => {
      const title = prompt('Task title:');

      if (!title) return;

      const assignedTo = prompt('User ID to assign (optional):');

      await fetch(API_URL + '/tasks', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          title,
          project_id: projectId,
          assigned_to: assignedTo || null
        })
      });

      load();
    };

    window.updateStatus = async (taskId, status) => {
      await fetch(API_URL + '/tasks/' + taskId + '/status', {
        method: 'PATCH',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status })
      });

      load();
    };

    function renderApp(user, dashboard, projects) {
      document.getElementById('root').innerHTML = \`
        <div class="container mx-auto p-4">
          <div class="flex justify-between items-center mb-6">
            <h1 class="text-3xl font-bold">Task Manager</h1>
            <div>
              👋 \${user.name}
              |
              <button onclick="logout()" class="text-red-600">Logout</button>
            </div>
          </div>

          <div class="grid grid-cols-5 gap-4 mb-8">
            <div class="bg-white p-4 rounded shadow">Total: \${dashboard.stats.total}</div>
            <div class="bg-yellow-100 p-4 rounded">Pending: \${dashboard.stats.pending}</div>
            <div class="bg-blue-100 p-4 rounded">In Progress: \${dashboard.stats.in_progress}</div>
            <div class="bg-green-100 p-4 rounded">Completed: \${dashboard.stats.completed}</div>
            <div class="bg-red-100 p-4 rounded">Overdue: \${dashboard.stats.overdue}</div>
          </div>

          <h2 class="text-xl font-bold mb-3">My Tasks</h2>

          <div class="space-y-2 mb-8">
            \${dashboard.tasks.map(t => \`
              <div class="bg-white p-3 rounded shadow flex justify-between">
                <div>
                  <b>\${t.title}</b> - \${t.project_name}
                  <br>
                  <small>Due: \${t.due_date || 'No date'}</small>
                </div>

                <div>
                  <select onchange="updateStatus('\${t.id}', this.value)" class="border rounded p-1">
                    \${['pending', 'in_progress', 'completed'].map(s => \`
                      <option \${t.status === s ? 'selected' : ''}>\${s}</option>
                    \`).join('')}
                  </select>
                </div>
              </div>
            \`).join('')}
          </div>

          <h2 class="text-xl font-bold mb-3">Projects</h2>

          <button onclick="createProject()" class="bg-blue-600 text-white px-4 py-2 rounded mb-4">
            + New Project
          </button>

          <div class="grid md:grid-cols-2 gap-4">
            \${projects.map(p => \`
              <div class="bg-white p-4 rounded shadow">
                <h3 class="font-bold text-lg">\${p.name}</h3>
                <p class="text-gray-600 mb-2">\${p.description || ''}</p>

                <button onclick="addMember('\${p.id}')" class="text-blue-600 text-sm mr-2">
                  + Add Member
                </button>

                <button onclick="createTask('\${p.id}')" class="text-green-600 text-sm">
                  + Task
                </button>
              </div>
            \`).join('')}
          </div>
        </div>
      \`;
    }

    load();
  </script>
</body>
</html>
  `);
});

app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});