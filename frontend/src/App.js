import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Toaster, toast } from 'sonner'; // Pastikan library sonner terinstall untuk notifikasi cantik
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import ChatRoom from './pages/ChatRoom';

// Konfigurasi Axios
const API_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8000';
const api = axios.create({ baseURL: `${API_URL}/api` });

// Interceptor untuk kirim Token otomatis
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Komponen Proteksi Route
const ProtectedRoute = ({ children }) => {
  const token = localStorage.getItem('token');
  if (!token) return <Navigate to="/login" replace />;
  return children;
};

function App() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans">
      <Toaster position="top-right" richColors />
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/chat/:sessionId" element={<ProtectedRoute><ChatRoom /></ProtectedRoute>} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;
