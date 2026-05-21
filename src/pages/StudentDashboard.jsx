import React, { useState, useEffect, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { Shield, Play, LogOut, Activity } from 'lucide-react';

export default function StudentDashboard() {
    const { user, token, logout } = useContext(AuthContext);
    const navigate = useNavigate();
    const [rooms, setRooms] = useState([]);

    useEffect(() => {
        fetchMyRooms();
    }, []);

    const fetchMyRooms = async () => {
        try {
            const res = await fetch('http://localhost:3001/api/rooms/student', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                setRooms(await res.json());
            }
        } catch (error) {
            console.error("Error cargando salas del alumno:", error);
        }
    };

    return (
        <div className="min-h-screen bg-slate-950 text-gray-100 p-8 font-sans">
            <header className="flex justify-between items-center mb-8 border-b border-slate-800 pb-4">
                <div className="flex items-center gap-3">
                    <Shield className="w-8 h-8 text-green-500" />
                    <div>
                        <h1 className="text-2xl font-bold">Panel de Estudiante</h1>
                        <p className="text-sm text-slate-400">{user?.email}</p>
                    </div>
                </div>
                <button onClick={() => { logout(); navigate('/login'); }} className="bg-red-900/30 text-red-400 border border-red-900 px-4 py-2 rounded font-bold text-sm">
                    <LogOut className="w-4 h-4 inline mr-2" /> Salir
                </button>
            </header>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                {/* Panel Izquierdo: Modo Libre */}
                <div className="md:col-span-1">
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl text-center">
                        <Activity className="w-12 h-12 text-blue-500 mx-auto mb-4" />
                        <h2 className="text-xl font-bold mb-2">Modo Libre</h2>
                        <p className="text-slate-400 text-sm mb-6">Explora el simulador sin restricciones, crea tus propias reglas y prueba ataques libremente.</p>
                        <button
                            onClick={() => navigate('/simulator')}
                            className="w-full bg-slate-800 hover:bg-slate-700 text-white border border-slate-600 font-bold py-3 rounded transition-colors"
                        >
                            Entrar al Sandbox
                        </button>
                    </div>
                </div>

                {/* Panel Derecho: Salas Asignadas */}
                <div className="md:col-span-2 space-y-4">
                    <h2 className="text-xl font-bold mb-4 border-b border-slate-800 pb-2">Misiones Asignadas (Salas)</h2>

                    {rooms.length === 0 ? (
                        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-500">
                            <p>No tienes ninguna sala asignada actualmente.</p>
                            <p className="text-sm mt-2">Pide a tu profesor que te invite usando tu correo: <strong className="text-slate-300">{user?.email}</strong></p>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            {rooms.map(room => (
                                <div key={room._id} className="bg-slate-900 border border-slate-700 hover:border-green-500 transition-colors rounded-xl p-6 shadow-md flex flex-col justify-between h-full">
                                    <div>
                                        <h3 className="text-lg font-bold text-green-400 mb-1">{room.name}</h3>
                                        <p className="text-xs text-slate-500 mb-4">Añadido el: {new Date(room.createdAt).toLocaleDateString()}</p>
                                    </div>

                                    <button
                                        onClick={() => navigate(`/simulator/${room._id}`)}
                                        className="w-full bg-green-600 hover:bg-green-700 text-white py-2 rounded text-sm font-bold flex items-center justify-center gap-2 mt-4"
                                    >
                                        <Play className="w-4 h-4" /> Iniciar Escenario
                                    </button>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}