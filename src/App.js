import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom'; // Quitamos el 'Navigate' porque ya no redirigimos por defecto
import { AuthProvider } from './context/AuthContext';
import LandingPage from './pages/LandingPage'; // <-- 1. IMPORTA LA LANDING PAGE
import AuthPage from './pages/AuthPage';
import TeacherDashboard from './pages/TeacherDashboard';
import StudentDashboard from './pages/StudentDashboard';
import MiComponente from './firewall_v3';

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<LandingPage />} />

          <Route path="/login" element={<AuthPage />} />
          <Route path="/register" element={<AuthPage />} /> {/* <-- AÑADE ESTA LÍNEA */}

          <Route path="/teacher-dashboard" element={<TeacherDashboard />} />
          <Route path="/student-dashboard" element={<StudentDashboard />} />

          <Route path="/simulator" element={<MiComponente />} />
          <Route path="/simulator/:roomId" element={<MiComponente />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;