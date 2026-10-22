// Data in-memory (hilang saat server restart). Cukup untuk demo; produksi pakai database.
const bcrypt = require("bcryptjs");

// Akun demo. Password plaintext hanya ada di sini untuk keperluan demo,
// saat start langsung di-hash bcrypt (salt acak, cost 10) dan plaintext dibuang.
const seedUsers = [
  { username: "admin", password: "admin123", name: "Admin RS", email: "admin@rs.local",
    role: "admin", department: "Manajemen", ward: null, clearance: 3, onDuty: true },
  { username: "dr.andi", password: "dokter123", name: "dr. Andi Wijaya", email: "andi@rs.local",
    role: "dokter", department: "Penyakit Dalam", ward: "Melati", clearance: 3, onDuty: true },
  { username: "dr.sari", password: "dokter123", name: "dr. Sari Kusuma", email: "sari@rs.local",
    role: "dokter", department: "Anak", ward: "Anggrek", clearance: 2, onDuty: true },
  { username: "ns.budi", password: "perawat123", name: "Ns. Budi Santoso", email: "budi@rs.local",
    role: "perawat", department: "Keperawatan", ward: "Melati", clearance: 3, onDuty: true },
  { username: "ns.citra", password: "perawat123", name: "Ns. Citra Ayu", email: "citra@rs.local",
    role: "perawat", department: "Keperawatan", ward: "Anggrek", clearance: 1, onDuty: false },
  { username: "dewi", password: "pasien123", name: "Dewi Lestari", email: "dewi@rs.local",
    role: "pasien", patientId: "P001" },
  { username: "eko", password: "pasien123", name: "Eko Prasetyo", email: "eko@rs.local",
    role: "pasien", patientId: "P002" },
];

const users = seedUsers.map(({ password, ...u }, i) => ({
  id: String(i + 1),
  googleId: null,
  ...u,
  passwordHash: bcrypt.hashSync(password, 10),
}));

// sensitivity: 1 = Umum, 2 = Sensitif, 3 = Rahasia
const records = [
  { id: 1, patientId: "P001", patientName: "Dewi Lestari", ward: "Melati", department: "Penyakit Dalam",
    sensitivity: 1, diagnosis: "Demam berdarah dengue", notes: [], createdBy: "dr.andi" },
  { id: 2, patientId: "P001", patientName: "Dewi Lestari", ward: "Melati", department: "Penyakit Dalam",
    sensitivity: 3, diagnosis: "Hasil skrining HIV", notes: [], createdBy: "dr.andi" },
  { id: 3, patientId: "P002", patientName: "Eko Prasetyo", ward: "Anggrek", department: "Anak",
    sensitivity: 1, diagnosis: "Demam tifoid", notes: [], createdBy: "dr.sari" },
  { id: 4, patientId: "P002", patientName: "Eko Prasetyo", ward: "Anggrek", department: "Anak",
    sensitivity: 2, diagnosis: "Riwayat konsultasi psikologi", notes: [], createdBy: "dr.sari" },
  { id: 5, patientId: "P003", patientName: "Fajar Nugroho", ward: "Melati", department: "Bedah",
    sensitivity: 2, diagnosis: "Pasca operasi apendektomi", notes: [], createdBy: "admin" },
];

module.exports = { users, records };
