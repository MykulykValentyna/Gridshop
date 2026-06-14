require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 5000; 
const SECRET_KEY = process.env.JWT_SECRET;
if (!SECRET_KEY) {
  console.error("КРИТИЧНА ПОМИЛКА: Не знайдено JWT_SECRET у файлі .env!");
  process.exit(1); 
}

// конфігурація та шляхи
const DATA_FILE = path.join(__dirname, 'data.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const AUDIT_FILE = path.join(__dirname, 'audit.json');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = 'uploads/';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// допоміжні функції баз даних
const readJson = (file) => {
  try {
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file, 'utf-8')) || [];
  } catch (error) {
    return [];
  }
};

const saveJson = (file, data) => {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf-8');
};

const logAction = (userEmail, action, itemId, details) => {
  const logs = readJson(AUDIT_FILE);
  logs.push({
    id: Date.now(),
    timestamp: new Date().toISOString(),
    user: userEmail || 'System',
    action,
    itemId,
    details
  });
  saveJson(AUDIT_FILE, logs);
};

// мілдвари авторизації та ролей
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: "Відсутній токен доступу" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: "Недійсний або протермінований токен" });
    req.user = user;
    next();
  });
};

const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Недостатньо прав для виконання цієї дії" });
    }
    next();
  };
};

// безпека та доступ
app.post('/api/auth/register', async (req, res) => {
  const { email, password, role = 'guest' } = req.body;
  const users = readJson(USERS_FILE);

  if (users.some(u => u.email === email)) {
    return res.status(400).json({ message: "Користувач із таким email вже існує" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now(), email, password: hashedPassword, role };
  
  users.push(newUser);
  saveJson(USERS_FILE, users);
  res.status(201).json({ message: "Користувача успішно створено" });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const users = readJson(USERS_FILE);
  const user = users.find(u => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ message: "Невірний email або пароль" });
  }

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET_KEY, { expiresIn: '12h' });
  res.json({ token, role: user.role, email: user.email });
});

// управління складом та оптимізація
app.get('/api/inventory', authenticateToken, authorizeRole(['admin', 'storekeeper', 'guest']), (req, res) => {
  let inventory = readJson(DATA_FILE);
  const { page = 1, limit = 20, category, status, search, assigned_to, sortBy = 'newest' } = req.query;

  if (category) inventory = inventory.filter(i => i.category === category);
  if (status) inventory = inventory.filter(i => i.status === status);
  if (assigned_to) inventory = inventory.filter(i => i.assigned_to === assigned_to);
  if (search) {
    const query = search.toLowerCase();
    inventory = inventory.filter(i => 
      i.inventory_name.toLowerCase().includes(query) || 
      (i.qr_code && i.qr_code.toLowerCase().includes(query))
    );
  }

  if (sortBy === 'newest') inventory.sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));
  else if (sortBy === 'oldest') inventory.sort((a, b) => new Date(a.updated_at) - new Date(b.updated_at));

  const pageNum = parseInt(page);
  const limitNum = parseInt(limit);
  const startIndex = (pageNum - 1) * limitNum;
  const paginatedResults = inventory.slice(startIndex, startIndex + limitNum);

  res.json({
    totalItems: inventory.length,
    totalPages: Math.ceil(inventory.length / limitNum),
    currentPage: pageNum,
    data: paginatedResults
  });
});

app.get('/api/inventory/:id', authenticateToken, authorizeRole(['admin', 'storekeeper', 'guest']), (req, res) => {
  const inventory = readJson(DATA_FILE);
  const item = inventory.find(i => i.id === parseInt(req.params.id));
  item ? res.json(item) : res.status(404).json({ message: "Одиницю інвентарю не знайдено" });
});

app.post('/api/inventory', authenticateToken, authorizeRole(['admin', 'storekeeper']), upload.single('photo'), (req, res) => {
  const { inventory_name, description = '', quantity = 1, status = 'нове', category = 'Не вказано', price = 0 } = req.body;
  
  if (!inventory_name) return res.status(400).json({ message: "Назва інвентарю є обов'язковою" });

  const inventory = readJson(DATA_FILE);
  const newItemId = Date.now();
  
  const newItem = {
    id: newItemId,
    inventory_name,
    description,
    quantity: parseInt(quantity),
    status,
    category,
    price: parseFloat(price),
    qr_code: `QR-${newItemId}`,
    assigned_to: null,
    photo_url: req.file ? `http://localhost:${PORT}/uploads/${req.file.filename}` : null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };

  inventory.push(newItem);
  saveJson(DATA_FILE, inventory);
  logAction(req.user.email, 'CREATE', newItem.id, `Створено нову позицію: ${inventory_name}`);

  res.status(201).json(newItem);
});

app.put('/api/inventory/:id', authenticateToken, authorizeRole(['admin', 'storekeeper']), (req, res) => {
  const inventory = readJson(DATA_FILE);
  const index = inventory.findIndex(i => i.id === parseInt(req.params.id));
  
  if (index === -1) return res.status(404).json({ message: "Одиницю інвентарю не знайдено" });

  inventory[index] = { 
    ...inventory[index], 
    ...req.body,
    id: inventory[index].id, 
    updated_at: new Date().toISOString()
  };
  
  saveJson(DATA_FILE, inventory);
  logAction(req.user.email, 'UPDATE', req.params.id, `Оновлено характеристики позиції`);
  res.json(inventory[index]);
});

app.put('/api/inventory/:id/photo', authenticateToken, authorizeRole(['admin', 'storekeeper']), upload.single('photo'), (req, res) => {
  const inventory = readJson(DATA_FILE);
  const index = inventory.findIndex(i => i.id === parseInt(req.params.id));
  
  if (index === -1) return res.status(404).json({ message: "Одиницю інвентарю не знайдено" });
  if (!req.file) return res.status(400).json({ message: "Файл фотографії не надано" });

  inventory[index].photo_url = `http://localhost:${PORT}/uploads/${req.file.filename}`;
  inventory[index].updated_at = new Date().toISOString();
  
  saveJson(DATA_FILE, inventory);
  logAction(req.user.email, 'UPDATE_PHOTO', req.params.id, `Оновлено фотографію позиції`);
  res.json(inventory[index]);
});

app.delete('/api/inventory/:id', authenticateToken, authorizeRole(['admin']), (req, res) => {
  let inventory = readJson(DATA_FILE);
  const itemExists = inventory.some(i => i.id === parseInt(req.params.id));
  
  if (!itemExists) return res.status(404).json({ message: "Одиницю інвентарю не знайдено" });

  inventory = inventory.filter(i => i.id !== parseInt(req.params.id));
  saveJson(DATA_FILE, inventory);
  logAction(req.user.email, 'DELETE', req.params.id, `Позицію видалено з бази даних`);
  res.status(204).send();
});

// логістика та рух майна
app.post('/api/inventory/:id/assign', authenticateToken, authorizeRole(['admin', 'storekeeper']), (req, res) => {
  const { assign_to } = req.body;
  const inventory = readJson(DATA_FILE);
  const index = inventory.findIndex(i => i.id === parseInt(req.params.id));

  if (index === -1) return res.status(404).json({ message: "Одиницю інвентарю не знайдено" });
  if (assign_to === undefined) return res.status(400).json({ message: "Не вказано відповідальну особу" });

  inventory[index].assigned_to = assign_to;
  inventory[index].updated_at = new Date().toISOString();
  saveJson(DATA_FILE, inventory);

  logAction(req.user.email, 'ASSIGN', req.params.id, `Статус закріплення змінено на: ${assign_to || 'На складі'}`);
  res.json(inventory[index]);
});

app.get('/api/audit-logs', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const logs = readJson(AUDIT_FILE);
  res.json(logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));
});

// аналітика та звіти
app.get('/api/analytics', authenticateToken, authorizeRole(['admin']), (req, res) => {
  const inventory = readJson(DATA_FILE);
  
  const stats = {
    totalItems: inventory.length,
    totalValue: inventory.reduce((sum, item) => sum + (parseFloat(item.price) || 0) * (parseInt(item.quantity) || 1), 0),
    statusBreakdown: {
      new: inventory.filter(i => i.status === 'нове').length,
      used: inventory.filter(i => i.status === 'вживане').length,
      inRepair: inventory.filter(i => i.status === 'в ремонті').length
    },
    assignedOut: inventory.filter(i => i.assigned_to !== null && i.assigned_to !== '').length,
    byCategory: inventory.reduce((acc, item) => {
      const cat = item.category || 'Інше';
      acc[cat] = (acc[cat] || 0) + 1;
      return acc;
    }, {})
  };

  res.json(stats);
});

app.get('/api/export/csv', authenticateToken, authorizeRole(['admin', 'storekeeper']), (req, res) => {
  const inventory = readJson(DATA_FILE);
  
  let csv = 'ID,Назва,Категорія,Статус,Кількість,Ціна,QR Код,Закріплено за,Останнє оновлення\n';
  inventory.forEach(item => {
    const cleanName = item.inventory_name ? item.inventory_name.replace(/"/g, '""') : '';
    const cleanAssignee = item.assigned_to ? item.assigned_to.replace(/"/g, '""') : 'На складі';
    
    csv += `${item.id},"${cleanName}","${item.category || ''}","${item.status || ''}",${item.quantity || 1},${item.price || 0},"${item.qr_code || ''}","${cleanAssignee}","${item.updated_at}"\n`;
  });

  res.header('Content-Type', 'text/csv; charset=utf-8');
  res.attachment(`inventory_report_${new Date().toISOString().split('T')[0]}.csv`);
  res.send(Buffer.from('\uFEFF' + csv));
});

// запуск сервера
app.listen(PORT, () => {
  console.log(`[SERVER] Запущено на порту ${PORT}`);
});