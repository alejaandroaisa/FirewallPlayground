import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Shield, Server, Users, Zap, CheckCircle, ChevronRight,
    Lock, Activity, Terminal, Layers, MessageSquare, Send, Key
} from 'lucide-react';

export default function LandingPage() {
    const navigate = useNavigate();

    return (
        <div className="min-h-screen bg-slate-950 text-slate-300 font-sans selection:bg-blue-500 selection:text-white">

            {/* BARRA DE NAVEGACIÓN */}
            <nav className="container mx-auto px-6 py-4 flex justify-between items-center border-b border-slate-800/50">
                <div className="flex items-center gap-2">
                    <Shield className="w-8 h-8 text-blue-500" />
                    <div className="flex items-center">
                        <span className="text-xl font-bold text-white tracking-wide">FireWall Playground</span>
                        <span className="ml-3 text-[10px] bg-gradient-to-r from-blue-600 to-cyan-500 text-white px-2 py-0.5 rounded-full uppercase font-bold tracking-wider">
                            Versión Beta
                        </span>
                    </div>
                </div>
                <div>
                    <button
                        onClick={() => navigate('/login')}
                        className="text-sm font-bold text-slate-300 hover:text-white transition-colors mr-6"
                    >
                        Iniciar Sesión
                    </button>
                    <button
                        onClick={() => navigate('/register')}
                        className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-bold py-2 px-5 rounded-full shadow-lg shadow-blue-900/20 transition-all"
                    >
                        Comenzar Gratis
                    </button>
                </div>
            </nav>

            {/* SECCIÓN HERO (Principal) */}
            <section className="container mx-auto px-6 py-20 lg:py-32 text-center relative overflow-hidden">
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-blue-600/10 rounded-full blur-[120px] pointer-events-none"></div>

                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-900/30 border border-blue-800/50 text-blue-300 text-sm mb-8 relative z-10">
                    <Activity className="w-4 h-4 animate-pulse" />
                    <span>Plataforma en fase Beta Activa - Únete y ayúdanos a mejorar</span>
                </div>

                <h1 className="text-5xl lg:text-7xl font-bold text-white mb-6 tracking-tight relative z-10 leading-tight">
                    Aprende Ciberseguridad <br className="hidden lg:block" />
                    <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-300">
                        Experimentando
                    </span>
                </h1>
                <p className="text-lg lg:text-xl text-slate-400 max-w-3xl mx-auto mb-10 relative z-10 leading-relaxed">
                    Un simulador educativo que transforma la teoría en práctica. Configura reglas de filtrado, audita tráfico en tiempo real mediante Inspección Profunda (DPI) y frena ciberataques sin poner en riesgo tu equipo ni instalar máquinas virtuales.
                </p>

                <div className="flex flex-col sm:flex-row justify-center gap-4 relative z-10">
                    <button
                        onClick={() => navigate('/register')}
                        className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-8 rounded-full flex items-center justify-center gap-2 transition-transform hover:scale-105"
                    >
                        Crear cuenta gratuita <ChevronRight className="w-5 h-5" />
                    </button>
                    <button
                        onClick={() => navigate('/simulator')}
                        className="bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 px-8 rounded-full border border-slate-700 transition-colors"
                    >
                        Probar Modo Libre (Sandbox)
                    </button>
                </div>
            </section>

            {/* SECCIÓN: ¿EN QUÉ CONSISTE EL SIMULADOR? */}
            <section className="bg-slate-900 border-y border-slate-800/50 py-20">
                <div className="container mx-auto px-6">
                    <div className="max-w-3xl mx-auto text-center mb-16">
                        <h2 className="text-3xl font-bold text-white mb-4">¿En qué consiste el simulador?</h2>
                        <p className="text-slate-400 leading-relaxed">
                            FireWall Playground es un entorno de pruebas web (Sandbox) que emula el comportamiento de un cortafuegos de red avanzado (Capa 7 OSI). Su objetivo es puramente educativo: permitir a los usuarios entender qué viaja exactamente por los cables de Internet y cómo los dispositivos deciden qué información bloquear o permitir.
                        </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-12">
                        <div className="text-center">
                            <div className="bg-slate-800 w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-inner border border-slate-700">
                                <Layers className="w-8 h-8 text-blue-400" />
                            </div>
                            <h3 className="text-xl font-bold text-white mb-3">1. Define Políticas</h3>
                            <p className="text-slate-400 text-sm">
                                Establece la regla de oro: <em>"Lo que no está explícitamente permitido, está denegado"</em>. Crea reglas basadas en IPs, protocolos (TCP/UDP/ICMP) y puertos específicos.
                            </p>
                        </div>
                        <div className="text-center">
                            <div className="bg-slate-800 w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-inner border border-slate-700">
                                <Terminal className="w-8 h-8 text-purple-400" />
                            </div>
                            <h3 className="text-xl font-bold text-white mb-3">2. Audita Paquetes</h3>
                            <p className="text-slate-400 text-sm">
                                Abre cualquier paquete interceptado. Analiza su estructura desde la Capa de Enlace (direcciones MAC) hasta la Capa de Aplicación, leyendo incluso su código Hexadecimal.
                            </p>
                        </div>
                        <div className="text-center">
                            <div className="bg-slate-800 w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-6 shadow-inner border border-slate-700">
                                <Shield className="w-8 h-8 text-red-400" />
                            </div>
                            <h3 className="text-xl font-bold text-white mb-3">3. Mitiga Amenazas</h3>
                            <p className="text-slate-400 text-sm">
                                Activa el inyector de ataques para simular una Inyección SQL o un ataque DDoS. Observa cómo sube la carga de la CPU y diseña una regla DPI (Deep Packet Inspection) para frenarlo.
                            </p>
                        </div>
                    </div>
                </div>
            </section>

            {/* SECCIÓN CARACTERÍSTICAS TÉCNICAS */}
            <section className="py-20">
                <div className="container mx-auto px-6">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl font-bold text-white mb-4">Motor de Seguridad Completo</h2>
                        <p className="text-slate-400">Implementa conceptos avanzados de ciberdefensa en unos pocos clics.</p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                        <div className="bg-slate-900 border border-slate-800 p-8 rounded-2xl hover:border-blue-500/50 transition-colors">
                            <Server className="w-7 h-7 text-blue-400 mb-4" />
                            <h3 className="text-xl font-bold text-white mb-3">Stateful Inspection</h3>
                            <p className="text-slate-400 text-sm leading-relaxed">
                                Aprende la diferencia entre un firewall sin estado y uno con estado (Stateful). Observa la tabla de conexiones activas y cómo el sistema recuerda las sesiones para permitir el tráfico de retorno.
                            </p>
                        </div>

                        <div className="bg-slate-900 border border-slate-800 p-8 rounded-2xl hover:border-orange-500/50 transition-colors">
                            <Zap className="w-7 h-7 text-orange-400 mb-4" />
                            <h3 className="text-xl font-bold text-white mb-3">Sistema IPS Integrado</h3>
                            <p className="text-slate-400 text-sm leading-relaxed">
                                El simulador incluye un Sistema de Prevención de Intrusiones (IPS) automatizado. Actívalo para que bloquee temporalmente direcciones IP que superen un umbral de peticiones sospechosas.
                            </p>
                        </div>

                        <div className="bg-slate-900 border border-slate-800 p-8 rounded-2xl hover:border-green-500/50 transition-colors lg:col-span-1 md:col-span-2">
                            <Lock className="w-7 h-7 text-green-400 mb-4" />
                            <h3 className="text-xl font-bold text-white mb-3">Logs de Tráfico en Vivo</h3>
                            <p className="text-slate-400 text-sm leading-relaxed">
                                El panel de monitorización captura cada evento. Filtra por direcciones IP, puertos o acciones (DROP/ACCEPT) para detectar rápidamente los cuellos de botella y firmas de malware.
                            </p>
                        </div>
                    </div>
                </div>
            </section>

            {/* SECCIÓN SISTEMA DE SALAS & TERMINAL */}
            <section className="bg-slate-900/50 container mx-auto px-6 py-20 rounded-3xl border border-slate-800 mb-20">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
                    <div>
                        <h2 className="text-3xl font-bold text-white mb-4">El sistema de salas</h2>
                        <p className="text-slate-400 mb-8 leading-relaxed">
                            Diseñado específicamente para academias y universidades. Olvídate de compartir archivos JSON o instalar pesadas máquinas virtuales (VMs). Todo ocurre en la nube mediante un flujo perfecto:
                        </p>

                        <ul className="space-y-6">
                            <li className="flex items-start gap-4">
                                <div className="bg-blue-900/30 p-3 rounded-xl border border-blue-800/50 mt-1 shadow-inner">
                                    <Users className="w-6 h-6 text-blue-400" />
                                </div>
                                <div>
                                    <strong className="text-white block mb-1 text-lg">1. El profesor diseña el reto</strong>
                                    <span className="text-slate-400 text-sm leading-relaxed block">
                                        Desde su panel de control, el docente configura un escenario de ataque (ej. un <em>SYN Flood</em> masivo). El sistema guarda la configuración en la base de datos y genera automáticamente un <strong>Código de Sala único</strong>.
                                    </span>
                                </div>
                            </li>
                            <li className="flex items-start gap-4">
                                <div className="bg-green-900/30 p-3 rounded-xl border border-green-800/50 mt-1 shadow-inner">
                                    <Key className="w-6 h-6 text-green-400" />
                                </div>
                                <div>
                                    <strong className="text-white block mb-1 text-lg">2. Los alumnos se conectan</strong>
                                    <span className="text-slate-400 text-sm leading-relaxed block">
                                        Los estudiantes introducen el código de la sala en su propio panel. Instantáneamente, son transportados al simulador con las condiciones de crisis exactas dictadas por el profesor.
                                    </span>
                                </div>
                            </li>
                            <li className="flex items-start gap-4">
                                <div className="bg-purple-900/30 p-3 rounded-xl border border-purple-800/50 mt-1 shadow-inner">
                                    <Activity className="w-6 h-6 text-purple-400" />
                                </div>
                                <div>
                                    <strong className="text-white block mb-1 text-lg">3. Supervivencia en tiempo real</strong>
                                    <span className="text-slate-400 text-sm leading-relaxed block">
                                        El alumno debe analizar el tráfico, encontrar la firma del ataque y aplicar reglas de firewall antes de que la CPU virtual colapse. Todo ello corriendo fluidamente desde cualquier navegador web.
                                    </span>
                                </div>
                            </li>
                        </ul>
                    </div>

                    {/* Ventana de Logs Decorativa */}
                    <div className="bg-slate-950 rounded-2xl p-6 border border-slate-700 shadow-2xl relative overflow-hidden h-full flex flex-col justify-center min-h-[400px]">
                        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-red-500 via-orange-500 to-blue-500"></div>
                        <div className="flex items-center justify-between mb-6 border-b border-slate-800 pb-4">
                            <div className="flex items-center gap-2">
                                <Server className="w-4 h-4 text-slate-500" />
                                <span className="font-mono text-xs text-slate-400 uppercase tracking-widest">Sala Activa: 4f8a-9b2c</span>
                            </div>
                            <span className="text-[10px] bg-red-900/30 text-red-400 px-2 py-1 rounded border border-red-800/50 font-mono">CPU: 98% (CRÍTICO)</span>
                        </div>

                        <div className="font-mono text-xs text-slate-300 space-y-3 opacity-90 flex-1">
                            <p className="text-slate-500 italic mb-4">{"//"} Conexión establecida al escenario del profesor. Iniciando inyector de tráfico...</p>

                            <p><span className="text-green-500 font-bold bg-green-900/20 px-1 rounded">[ACCEPT]</span> TCP 192.168.1.45:54312 -{">"} 10.0.0.5:80 (SYN)</p>
                            <p><span className="text-blue-400 font-bold bg-blue-900/20 px-1 rounded">[STATEFUL]</span> TCP 10.0.0.5:80 -{">"} 192.168.1.45:54312 (SYN, ACK)</p>
                            <p><span className="text-red-500 font-bold bg-red-900/20 px-1 rounded">[DROP]</span> UDP 192.168.1.99:12345 -{">"} 10.0.0.5:53 <span className="text-red-400 ml-2 animate-pulse">!DDoS Payload!</span></p>
                            <p><span className="text-red-500 font-bold bg-red-900/20 px-1 rounded">[DROP]</span> TCP 192.168.1.33:5555 -{">"} 10.0.0.5:80 <span className="text-orange-400 ml-2">!SQLi Signature!</span></p>
                            <p><span className="text-red-500 font-bold bg-red-900/20 px-1 rounded">[DROP]</span> UDP 192.168.1.102:4444 -{">"} 10.0.0.5:53 <span className="text-red-400 ml-2 animate-pulse">!DDoS Payload!</span></p>
                        </div>
                    </div>
                </div>
            </section>

            {/* SECCIÓN DE FEEDBACK */}
            <section className="container mx-auto px-6 py-20">
                <div className="max-w-4xl mx-auto bg-slate-900/80 border border-slate-800 rounded-3xl p-8 md:p-12 shadow-2xl relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-64 h-64 bg-blue-600/10 rounded-full blur-[80px] pointer-events-none"></div>

                    <div className="text-center mb-10 relative z-10">
                        <MessageSquare className="w-12 h-12 text-blue-500 mx-auto mb-4" />
                        <h2 className="text-3xl font-bold text-white mb-2">Ayúdanos a Mejorar</h2>
                        <p className="text-slate-400">¿Has encontrado un error o tienes una idea genial? Al estar en fase Beta, tu opinión es muy importante para nosotros.</p>
                    </div>

                    <form
                        action="https://formsubmit.co/aisacoras5@gmail.com"
                        method="POST"
                        className="space-y-6 relative z-10 max-w-2xl mx-auto"
                    >
                        <input type="hidden" name="_subject" value="Nuevo Feedback - FireWall Playground Beta" />
                        <input type="hidden" name="_captcha" value="false" />
                        <input type="hidden" name="_template" value="box" />

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <label className="block text-sm font-bold text-slate-300 mb-2">Nombre</label>
                                <input
                                    type="text"
                                    name="Nombre"
                                    required
                                    placeholder="Tu nombre o alias"
                                    className="w-full p-3 rounded-lg bg-slate-950 border border-slate-700 text-white focus:border-blue-500 focus:outline-none transition-colors"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-bold text-slate-300 mb-2">Email</label>
                                <input
                                    type="email"
                                    name="Email"
                                    required
                                    placeholder="tu@email.com"
                                    className="w-full p-3 rounded-lg bg-slate-950 border border-slate-700 text-white focus:border-blue-500 focus:outline-none transition-colors"
                                />
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm font-bold text-slate-300 mb-2">Mensaje</label>
                            <textarea
                                name="Mensaje"
                                required
                                rows="4"
                                placeholder="Cuéntanos qué te parece, qué fallos has visto o qué funciones nuevas te gustarían..."
                                className="w-full p-3 rounded-lg bg-slate-950 border border-slate-700 text-white focus:border-blue-500 focus:outline-none transition-colors resize-none"
                            ></textarea>
                        </div>

                        <button
                            type="submit"
                            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
                        >
                            <Send className="w-5 h-5" /> Enviar Feedback
                        </button>
                    </form>
                </div>
            </section>

            {/* FOOTER */}
            <footer className="bg-slate-950 border-t border-slate-900 py-10 text-center">
                <div className="flex justify-center items-center gap-2 mb-4">
                    <Shield className="w-6 h-6 text-slate-600" />
                    <span className="text-lg font-bold text-slate-500 tracking-wide">FireWall Playground</span>
                    <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded-full uppercase font-bold tracking-wider">Beta</span>
                </div>
                <p className="text-sm text-slate-600">
                    Proyecto Educativo Creado por Alejandro Aisa © {new Date().getFullYear()}
                </p>
            </footer>
        </div>
    );
}