import React, { useState, useEffect, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { Shield, Plus, LogOut, Settings } from 'lucide-react';

export default function TeacherDashboard() {
    const { user, token, logout } = useContext(AuthContext);
    const navigate = useNavigate();
    const [rooms, setRooms] = useState([]);
    const [roomName, setRoomName] = useState('');
    const [inviteEmails, setInviteEmails] = useState({});

    useEffect(() => {
        fetchRooms();
    }, []);

    const fetchRooms = async () => {
        try {
            const res = await fetch('http://localhost:3001/api/rooms/teacher', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) setRooms(await res.json());
        } catch (error) { console.error(error); }
    };

    const handleCreateRoom = async (e) => {
        e.preventDefault();
        try {
            // Creamos la sala con una configuración inicial básica
            const defaultConfiguration = { rules: [], defaultPolicy: 'DROP', isStateful: false, isAutoDefense: false };

            const res = await fetch('http://localhost:3001/api/rooms', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ name: roomName, configuration: defaultConfiguration })
            });

            if (res.ok) {
                setRoomName('');
                fetchRooms();
            }
        } catch (err) { console.error(err); }
    };

    const handleInvite = async (roomId) => {
        if (!inviteEmails[roomId]) return;
        // Separa correos por comas y limpia espacios
        const emailArray = inviteEmails[roomId].split(',').map(e => e.trim()).filter(e => e);
        try {
            const res = await fetch(`http://localhost:3001/api/rooms/${roomId}/invite`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ studentEmails: emailArray })
            });
            if (res.ok) {
                setInviteEmails({ ...inviteEmails, [roomId]: '' });
                fetchRooms(); // Refresca la lista de alumnos en pantalla
            }
        } catch (error) { console.error(error); }
    };

    return (
        <div className="min-h-screen bg-slate-950 text-gray-100 p-8 font-sans">
            <header className="flex justify-between items-center mb-8 border-b border-slate-800 pb-4">
                <div className="flex items-center gap-3">
                    <Shield className="w-8 h-8 text-blue-500" />
                    <div>
                        <h1 className="text-2xl font-bold">Panel de Profesor</h1>
                        <p className="text-sm text-slate-400">{user?.email}</p>
                    </div>
                </div>
                <button onClick={() => { logout(); navigate('/login'); }} className="bg-red-900/30 text-red-400 border border-red-900 px-4 py-2 rounded font-bold text-sm">
                    <LogOut className="w-4 h-4 inline mr-2" /> Salir
                </button>
            </header>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Crear Sala */}
                <div className="lg:col-span-1">
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
                        <h2 className="text-xl font-bold mb-4 flex items-center gap-2"><Plus className="w-5 h-5 text-blue-400" /> Crear Sala</h2>
                        <form onSubmit={handleCreateRoom} className="space-y-4">
                            <input type="text" required placeholder="Nombre de la Sala" className="w-full p-2 rounded bg-slate-800 border border-slate-600 text-white" value={roomName} onChange={(e) => setRoomName(e.target.value)} />
                            <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded">Crear Sala</button>
                        </form>
                    </div>
                </div>

                {/* Lista de Salas */}
                <div className="lg:col-span-2 space-y-4">
                    <h2 className="text-xl font-bold mb-4 border-b border-slate-800 pb-2">Mis Salas</h2>
                    {rooms.map(room => (
                        <div key={room._id} className="bg-slate-900 border border-slate-700 rounded-xl p-6 shadow-md flex flex-col gap-4">
                            <div className="flex justify-between items-start">
                                <h3 className="text-lg font-bold text-blue-300">{room.name}</h3>
                                {/* BOTÓN PARA IR AL SIMULADOR A CONFIGURAR ESTA SALA */}
                                <button
                                    onClick={() => navigate(`/simulator/${room._id}`)}
                                    className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded text-sm font-bold flex items-center gap-2"
                                >
                                    <Settings className="w-4 h-4" /> Configurar Escenario
                                </button>
                            </div>

                            {/* Gestión de Alumnos */}
                            <div className="bg-slate-950 p-4 rounded border border-slate-800">
                                <p className="text-xs font-bold text-slate-400 mb-2">Alumnos: {room.allowedStudents?.length || 0}</p>
                                <div className="flex flex-wrap gap-2 mb-3">
                                    {room.allowedStudents?.map((email, idx) => (
                                        <span key={idx} className="bg-slate-800 text-slate-300 border border-slate-700 px-2 py-1 rounded text-xs">{email}</span>
                                    ))}
                                </div>
                                <div className="flex gap-2">
                                    <input type="text" placeholder="Añadir alumno@email.com" className="flex-1 p-2 text-sm rounded bg-slate-800 border border-slate-600 text-white" value={inviteEmails[room._id] || ''} onChange={(e) => setInviteEmails({ ...inviteEmails, [room._id]: e.target.value })} />
                                    <button onClick={() => handleInvite(room._id)} className="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded text-sm font-bold">Invitar</button>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}