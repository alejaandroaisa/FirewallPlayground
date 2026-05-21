import React, { useState, useContext } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import { Shield } from 'lucide-react';

export default function AuthPage() {
    // 1. PRIMERO inicializamos las herramientas de navegación y contexto
    const navigate = useNavigate();
    const location = useLocation();
    const { login } = useContext(AuthContext);

    // 2. DESPUÉS inicializamos los estados (ahora location ya existe)
    const [isLogin, setIsLogin] = useState(location.pathname !== '/register');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [role, setRole] = useState('STUDENT');
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
        const body = isLogin ? { email, password } : { email, password, role };

        try {
            // Asegúrate de poner TU url real de vercel y que empiece por https://
            const response = await fetch(`https://firewall-backend.vercel.app${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'Error en la autenticación');
            }

            if (isLogin) {
                // Si es login exitoso, guardamos token y redirigimos
                login(data.user, data.token);
                if (data.user.role === 'TEACHER') {
                    navigate('/teacher-dashboard');
                } else {
                    navigate('/student-dashboard');
                }
            } else {
                // Si es registro exitoso, pasamos a modo login
                setIsLogin(true);
                alert('Registro exitoso. Ahora puedes iniciar sesión.');
            }
        } catch (err) {
            setError(err.message);
        }
    };

    return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 font-sans text-gray-100">
            <div className="bg-slate-900 border border-slate-700 rounded-xl p-8 max-w-md w-full shadow-2xl">
                <div className="flex flex-col items-center mb-8">
                    <Shield className="w-12 h-12 text-blue-500 mb-2" />
                    <h1 className="text-2xl font-bold">FireWall Playground</h1>
                    <p className="text-slate-400 text-sm">Academia de Ciberseguridad</p>
                </div>

                {error && <div className="bg-red-900/30 border border-red-500 text-red-400 p-3 rounded mb-4 text-sm">{error}</div>}

                <form onSubmit={handleSubmit} className="space-y-4">
                    <div>
                        <label className="block text-sm font-bold text-slate-300 mb-1">Email</label>
                        <input
                            type="email"
                            className="w-full p-2 rounded bg-slate-800 border border-slate-600 text-white focus:border-blue-500 focus:outline-none"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-bold text-slate-300 mb-1">Contraseña</label>
                        <input
                            type="password"
                            className="w-full p-2 rounded bg-slate-800 border border-slate-600 text-white focus:border-blue-500 focus:outline-none"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                        />
                    </div>

                    {!isLogin && (
                        <div>
                            <label className="block text-sm font-bold text-slate-300 mb-1">Soy un...</label>
                            <select
                                className="w-full p-2 rounded bg-slate-800 border border-slate-600 text-white focus:border-blue-500 focus:outline-none"
                                value={role}
                                onChange={(e) => setRole(e.target.value)}
                            >
                                <option value="STUDENT">Alumno</option>
                                <option value="TEACHER">Profesor</option>
                            </select>
                        </div>
                    )}

                    <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded transition-colors mt-6">
                        {isLogin ? 'Entrar' : 'Registrarse'}
                    </button>
                </form>

                <div className="mt-6 text-center text-sm text-slate-400">
                    {isLogin ? "¿No tienes cuenta? " : "¿Ya tienes cuenta? "}
                    <button type="button" onClick={() => setIsLogin(!isLogin)} className="text-blue-400 hover:text-blue-300 font-bold underline">
                        {isLogin ? 'Regístrate' : 'Inicia Sesión'}
                    </button>
                </div>
            </div>
        </div>
    );
}