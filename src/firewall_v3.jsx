import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, Play, Pause, Plus, Trash2, ArrowUp, ArrowDown, Activity,
  FileText, Download, AlertTriangle, Settings, HelpCircle, RefreshCw,
  Zap, Database, Globe, CheckCircle, X, Layers, Binary, GraduationCap,
  ChevronRight, Move, Cpu, Siren, Clock, Save, Upload, Moon, Sun
} from 'lucide-react';

// IMPORTACIÓN DE UTILIDADES Y DATOS
import {
  PROTOCOLS,
  ACTIONS,
  BAN_DURATION,
  SERVER_MAC,
  ATTACK_TYPES,
  TUTORIAL_STEPS,
  generateMAC,
  generatePacket,
  generateHexDump
} from './firewall.utils';

import logo from './logo.png';

//Componentes UI Auxiliares

const EduTooltip = ({ text, align = 'center', side = 'top' }) => {
  const positionClasses = {
    center: 'left-1/2 transform -translate-x-1/2',
    left: 'left-0',
    right: 'right-0'
  };
  const arrowClasses = {
    center: 'left-1/2 transform -translate-x-1/2',
    left: 'left-1.5',
    right: 'right-1.5'
  };
  const isTop = side === 'top';
  const tooltipPos = isTop ? 'bottom-full mb-2' : 'top-full mt-2';
  const arrowPos = isTop ? 'top-full border-t-slate-800' : 'bottom-full border-b-slate-800';

  return (
    <span className="group/tooltip relative inline-block ml-2 cursor-help align-middle">
      <HelpCircle className="w-3 h-3 text-blue-400 hover:text-blue-600 transition-colors inline" />
      <span className={`invisible group-hover/tooltip:visible opacity-0 group-hover/tooltip:opacity-100 transition-opacity absolute ${tooltipPos} ${positionClasses[align]} px-3 py-2 bg-slate-800 text-white text-xs rounded shadow-xl w-64 text-center z-[100] pointer-events-none whitespace-normal normal-case font-normal border border-slate-600 leading-snug`}>
        {text}
        <span className={`absolute ${arrowPos} ${arrowClasses[align]} border-4 border-transparent`}></span>
      </span>
    </span>
  );
};

//Inspector de paquetes
const PacketInspector = ({ packet, onClose, darkMode }) => {
  if (!packet) return null;

  const hexDump = generateHexDump(packet);

  // Cálculos reales de longitudes
  const ipHeaderLen = 20; // 20 bytes (sin opciones)
  const l4HeaderLen = packet.protocol === 'TCP' ? 20 : packet.protocol === 'UDP' ? 8 : 8; // TCP min 20, UDP 8, ICMP 8
  const payloadLen = packet.payload ? packet.payload.length : 0;
  const ipTotalLength = ipHeaderLen + l4HeaderLen + payloadLen;

  // Estilos dinámicos para modo oscuro en el inspector
  const modalBg = darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-gray-200';
  const textMain = darkMode ? 'text-gray-200' : 'text-gray-800';
  const textSub = darkMode ? 'text-gray-400' : 'text-gray-500';
  const sectionBg = darkMode ? 'bg-slate-900 border-slate-800' : 'bg-white border-gray-200';
  const contentBg = darkMode ? 'bg-slate-950 border-slate-800' : 'bg-gray-50 border-gray-100';
  const summaryHover = darkMode ? 'hover:bg-slate-800' : 'hover:bg-gray-50';

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black bg-opacity-70 backdrop-blur-sm p-4 animate-fade-in font-sans">
      <div className={`rounded-xl shadow-2xl max-w-4xl w-full overflow-hidden flex flex-col max-h-[90vh] border ${modalBg}`}>
        {/* Header */}
        <div className="bg-slate-900 p-4 text-white flex justify-between items-center border-b border-slate-700">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${packet.action === 'DROP' ? 'bg-red-600' : 'bg-green-600'}`}>
              {packet.action === 'DROP' ? <Shield className="w-5 h-5 text-white" /> : <Layers className="w-5 h-5 text-white" />}
            </div>
            <div>
              <h2 className="text-lg font-bold">Inspector de Paquete: <span className={packet.action === 'DROP' ? 'text-red-400' : 'text-green-400'}>{packet.action}</span></h2>
              <p className="text-xs text-blue-200 font-mono">Frame {Math.floor(packet.id).toString().slice(-4)} | {packet.timestamp} | {packet.protocol}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white hover:bg-slate-800 p-2 rounded-full transition-colors">
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Content - Scrollable */}
        <div className={`overflow-y-auto p-0 flex-1 ${darkMode ? 'bg-slate-950' : 'bg-gray-50'}`}>

          {/* Layer 2: Ethernet */}
          <details open className={`border-b ${sectionBg}`}>
            <summary className={`px-4 py-2 cursor-pointer ${summaryHover} flex items-center justify-between select-none`}>
              <div className={`font-bold text-sm ${textMain} flex items-center gap-2`}>
                <span className="bg-gray-700 text-white text-[10px] px-1.5 rounded font-mono">L2</span>
                Ethernet II (Capa de Enlace)
              </div>
              <span className="text-xs text-gray-400">14 bytes</span>
            </summary>
            <div className={`px-6 py-3 text-xs font-mono grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 border-t ${contentBg}`}>
              {/* Columna Izquierda */}
              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  Destino
                  <EduTooltip align="left" side="bottom" text="Dirección MAC (física) de la tarjeta de red que recibe los pulsos eléctricos." />:
                </span>
                <span>{packet.destMAC}</span>
              </div>

              {/* Columna Derecha */}
              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  Origen
                  <EduTooltip align="right" side="bottom" text="Dirección MAC (física) del dispositivo que puso este paquete en el cable." />:
                </span>
                <span>{packet.sourceMAC}</span>
              </div>

              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  Tipo
                  <EduTooltip align="left" side="bottom" text="Hexadecimal (0x0800) que dice 'Lo que hay dentro es un paquete IPv4'." />:
                </span>
                <span>IPv4 (0x0800)</span>
              </div>
            </div>
          </details>

          {/* Layer 3: IP */}
          <details open className={`border-b ${sectionBg}`}>
            <summary className={`px-4 py-2 cursor-pointer ${summaryHover} flex items-center justify-between select-none`}>
              <div className={`font-bold text-sm ${textMain} flex items-center gap-2`}>
                <span className="bg-blue-600 text-white text-[10px] px-1.5 rounded font-mono">L3</span>
                Internet Protocol v4 (Capa de Red)
              </div>
              <span className="text-xs text-gray-400">20 bytes</span>
            </summary>
            <div className={`px-6 py-3 text-xs font-mono grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 border-t ${contentBg}`}>

              {/* Columna Izquierda */}
              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  Versión:
                  <EduTooltip align="left" text="4 para IPv4. Si fuera 6, la estructura de la cabecera sería totalmente distinta." />
                </span>
                <span>4</span>
              </div>

              {/* Columna Derecha */}
              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  Longitud Total
                  <EduTooltip align="right" text="Suma total de bytes: Cabecera IP (20) + Cabecera TCP/UDP + Datos del payload." />:
                </span>
                <span className="font-bold">{ipTotalLength} bytes</span>
              </div>

              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  Identificación:
                  <EduTooltip align="left" text="ID único usado para rearmar el paquete si este es fragmentado en trozos más pequeños por el camino." />
                </span>
                <span>0x{packet.id_ip ? packet.id_ip.toString(16).padStart(4, '0').toUpperCase() : '0000'}</span>
              </div>

              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  TTL (Time to Live):
                  <EduTooltip align="right" text="Contador de 'saltos'. Cada router lo baja en 1. Si llega a 0, el paquete muere (evita bucles infinitos)." />
                </span>
                <span>{packet.ttl}</span>
              </div>

              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  Protocolo:
                  <EduTooltip align="left" text="Indica qué intérprete usar para la siguiente capa. 6=TCP, 17=UDP, 1=ICMP." />
                </span>
                <span>{packet.protocol} ({packet.protocol === 'TCP' ? 6 : packet.protocol === 'UDP' ? 17 : 1})</span>
              </div>

              <div className="flex justify-between items-center md:col-start-2">
                {/* Espaciador */}
              </div>

              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  IP Origen:
                  <EduTooltip align="left" text="Dirección lógica (como una dirección postal) de quién envía el mensaje en Internet." />
                </span>
                <span className="font-bold">{packet.sourceIP}</span>
              </div>

              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  IP Destino:
                  <EduTooltip align="right" text="Dirección lógica final hacia donde debe enrutarse este paquete." />
                </span>
                <span className="font-bold">{packet.destIP}</span>
              </div>
            </div>
          </details>

          {/* Layer 4: Transport */}
          <details open className={`border-b ${sectionBg}`}>
            <summary className={`px-4 py-2 cursor-pointer ${summaryHover} flex items-center justify-between select-none`}>
              <div className={`font-bold text-sm ${textMain} flex items-center gap-2`}>
                <span className="bg-purple-600 text-white text-[10px] px-1.5 rounded font-mono">L4</span>
                {packet.protocol === 'TCP' ? 'Transmission Control Protocol' : packet.protocol === 'UDP' ? 'User Datagram Protocol' : 'ICMP'} (Capa de Transporte)
              </div>
              <span className="text-xs text-gray-400">{l4HeaderLen} bytes</span>
            </summary>
            <div className={`px-6 py-3 text-xs font-mono grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 border-t ${contentBg}`}>

              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  Puerto Origen:
                  <EduTooltip align="left" text="Canal de salida. En clientes suele ser un número alto aleatorio (ej: 54321)." />
                </span>
                <span>{packet.srcPort}</span>
              </div>

              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  Puerto Destino:
                  <EduTooltip align="right" text="Canal de servicio específico (ej: 80=Web, 22=SSH). Define qué aplicación recibirá los datos." />
                </span>
                <span className={`font-bold ${darkMode ? 'text-purple-400' : 'text-purple-700'}`}>{packet.destPort}</span>
              </div>

              {packet.protocol === 'TCP' && (
                <>
                  <div className={`flex justify-between items-center ${textMain}`}>
                    <span className={`${textSub} flex items-center gap-1`}>
                      Sequence Number:
                      <EduTooltip align="left" text="Número para ordenar los trozos de datos si llegan desordenados." />
                    </span>
                    <span>{packet.seq_num || 0}</span>
                  </div>
                  <div className={`flex justify-between items-center ${textMain}`}>
                    <span className={`${textSub} flex items-center gap-1`}>
                      Ack Number:
                      <EduTooltip align="right" text="Acuse de recibo. Dice 'He recibido todo hasta el byte X, mándame el siguiente'." />
                    </span>
                    <span>{packet.ack_num || 0}</span>
                  </div>
                  <div className={`flex justify-between items-center ${textMain}`}>
                    <span className={`${textSub} flex items-center gap-1`}>
                      Flags:
                      <EduTooltip align="left" text="Banderas de control: SYN (conectar), ACK (confirmar), FIN (terminar), PSH (enviar datos)." />
                    </span>
                    <span className={`font-bold ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{packet.flags}</span>
                  </div>
                  <div className={`flex justify-between items-center ${textMain}`}>
                    <span className={`${textSub} flex items-center gap-1`}>
                      Window Size:
                      <EduTooltip align="right" text="Control de flujo. Dice 'tengo X espacio libre en mi memoria, no me envíes más que eso'." />
                    </span>
                    <span>{packet.window_size || 65535}</span>
                  </div>
                </>
              )}
              {packet.protocol === 'UDP' && (
                <div className={`flex justify-between items-center ${textMain}`}>
                  <span className={`${textSub} flex items-center gap-1`}>
                    Length (Header+Data):
                    <EduTooltip align="left" text="UDP es simple: solo dice cuánto mide el mensaje completo. No hay acuses de recibo." />
                  </span>
                  <span>{8 + payloadLen} bytes</span>
                </div>
              )}
              <div className={`flex justify-between items-center ${textMain}`}>
                <span className={`${textSub} flex items-center gap-1`}>
                  Checksum:
                  {/* FIX: Lógica condicional para evitar desbordamiento. Si es UDP, está a la derecha (align right). Si es TCP, está a la izquierda (align left). */}
                  <EduTooltip align={packet.protocol === 'UDP' ? 'right' : 'left'} text="Suma matemática para verificar que ningún bit se corrompió por ruido eléctrico en el camino." />
                </span>
                <span>0x{packet.checksum || 'FAKE'}</span>
              </div>
            </div>
          </details>

          {/* Layer 7: Application / Hex Dump */}
          <details open className={`border-b ${sectionBg}`}>
            <summary className={`px-4 py-2 cursor-pointer ${summaryHover} flex items-center justify-between select-none`}>
              <div className={`font-bold text-sm ${textMain} flex items-center gap-2`}>
                <span className="bg-orange-600 text-white text-[10px] px-1.5 rounded font-mono">Data</span>
                Capa de Aplicación / Datos (Payload)
              </div>
              <span className="text-xs text-gray-400">{payloadLen} bytes</span>
            </summary>

            <div className={`p-4 border-t ${contentBg}`}>
              {/* Hexadecimal*/}
              {packet.payload && (
                <div className="mb-4">
                  <p className="text-xs text-gray-500 uppercase mb-1 font-bold flex items-center gap-1">
                    Payload (Texto Legible)
                    <EduTooltip align="center" text="La información útil para el usuario (HTML, JSON, Comandos) decodificada a texto ASCII." />
                  </p>
                  <div className={`border p-2 rounded text-xs font-mono break-all shadow-inner ${darkMode ? 'bg-slate-900 border-slate-700 text-green-400' : 'bg-white border-gray-200 text-green-700'}`}>
                    {packet.payload}
                  </div>
                </div>
              )}

              {/* Hex Dump */}
              <div>
                <div className="flex justify-between items-end mb-1">
                  <p className="text-xs text-gray-500 uppercase font-bold flex items-center gap-1">
                    <Binary className="w-3 h-3" /> Vista Hexadecimal (Raw)
                    <EduTooltip align="center" side="top" text="Vista real de los bytes que viajan por el cable. La columna izq es la posición, la central son los bytes en hex, la derecha es su representación ASCII." />
                  </p>
                  {packet.attackType === 'SQL Injection' && <span className={`text-[10px] text-red-600 font-bold px-2 py-0.5 rounded border ${darkMode ? 'bg-red-900/30 border-red-900' : 'bg-red-50 border-red-100'}`}>MALICIOUS PAYLOAD DETECTED</span>}
                </div>
                <div className="bg-slate-900 text-gray-300 p-3 rounded font-mono text-[10px] leading-relaxed shadow-inner overflow-x-auto selection:bg-blue-500 selection:text-white">
                  {hexDump.map((line, i) => (
                    <div key={i} className="hover:bg-slate-800 hover:text-white transition-colors cursor-text">
                      <span className="text-slate-500 select-none mr-3 border-r border-slate-700 pr-2">{line.split("   ")[0]}</span>
                      <span className="text-yellow-100 mr-4">{line.split("   ")[1]}</span>
                      <span className="text-cyan-400 opacity-70 border-l border-slate-700 pl-2">{line.split("   ")[2]}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </details>

        </div>

        {/* Footer */}
        <div className={`p-3 border-t text-right ${darkMode ? 'bg-slate-900 border-slate-700' : 'bg-gray-100 border-gray-200'}`}>
          <button onClick={onClose} className={`font-bold py-2 px-6 rounded text-sm transition-colors shadow-sm ${darkMode ? 'bg-slate-800 hover:bg-slate-700 text-white' : 'bg-slate-800 hover:bg-slate-900 text-white'}`}>
            Cerrar
          </button>
        </div>
      </div>
    </div>
  );
};

//Componente Principal

export default function FirewallSimulator() {
  const [isRunning, setIsRunning] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [defaultPolicy, setDefaultPolicy] = useState('DROP');
  const [showIntro, setShowIntro] = useState(true);

  //Estado para Modo Oscuro
  const [darkMode, setDarkMode] = useState(false);

  //Estados para Auto-Defensa (IPS) y Carga de Sistema
  const [isAutoDefense, setIsAutoDefense] = useState(false);
  const [systemLoad, setSystemLoad] = useState(5);
  const [timeNow, setTimeNow] = useState(Date.now());

  //Estados del Tutorial
  const [tutorialMode, setTutorialMode] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [showTutorialSuccess, setShowTutorialSuccess] = useState(false);
  const [stepComplete, setStepComplete] = useState(false);

  //Estados para arrastrar el widget
  const [tutorialPosition, setTutorialPosition] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const dragOffset = useRef({ x: 0, y: 0 });
  const tutorialWidgetRef = useRef(null);
  const fileInputRef = useRef(null);

  const [isStateful, setIsStateful] = useState(false);
  const [connections, setConnections] = useState([]);
  const [attackMode, setAttackMode] = useState(ATTACK_TYPES.NONE);
  const [selectedPacket, setSelectedPacket] = useState(null);

  const [rules, setRules] = useState([
    { id: 1, name: 'Permitir Web HTTP', sourceIP: '*', destIP: '*', protocol: 'TCP', port: '80', action: 'ACCEPT', content: '' },
    { id: 2, name: 'Permitir Web HTTPS', sourceIP: '*', destIP: '*', protocol: 'TCP', port: '443', action: 'ACCEPT', content: '' },
    { id: 3, name: 'Bloquear SSH Externo', sourceIP: '*', destIP: '*', protocol: 'TCP', port: '22', action: 'DROP', content: '' },
    { id: 4, name: 'Bloquear SQL Injection', sourceIP: '*', destIP: '*', protocol: '*', port: '*', action: 'DROP', content: 'SELECT *' },
  ]);

  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    allowed: 0,
    blocked: 0,
    attackAttempts: 0,
    statefulMatches: 0
  });

  const [newRule, setNewRule] = useState({
    name: '', sourceIP: '*', destIP: '*', protocol: 'TCP', port: '*', action: 'ACCEPT', content: ''
  });

  const [manualPacket, setManualPacket] = useState({
    sourceIP: '1.2.3.4', destIP: '10.0.0.5', protocol: 'TCP', destPort: '80', payload: ''
  });

  const stateRef = useRef({
    rules, defaultPolicy, isStateful, connections, attackMode, isAutoDefense
  });

  //Refs para análisis de tráfico
  const trafficAnalysisRef = useRef({
    ips: {},
    ports: {}
  });

  useEffect(() => {
    stateRef.current = { rules, defaultPolicy, isStateful, connections, attackMode, isAutoDefense };
  }, [rules, defaultPolicy, isStateful, connections, attackMode, isAutoDefense]);

  //Timer Global (para expiración reglas y UI)
  useEffect(() => {
    const timer = setInterval(() => {
      setTimeNow(Date.now());

      // Limpiar reglas expiradas
      setRules(prevRules => {
        const now = Date.now();
        // Solo filtrar si hay alguna expirada para evitar re-renders innecesarios
        const hasExpired = prevRules.some(r => r.expiresAt && r.expiresAt <= now);
        if (hasExpired) {
          return prevRules.filter(r => !r.expiresAt || r.expiresAt > now);
        }
        return prevRules;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  //Efecto de arrastre de la ventana del tutorial
  useEffect(() => {
    const handleMouseMove = (e) => {
      if (isDragging) {
        setTutorialPosition({
          x: e.clientX - dragOffset.current.x,
          y: e.clientY - dragOffset.current.y
        });
      }
    };
    const handleMouseUp = () => setIsDragging(false);

    if (isDragging) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', handleMouseUp);
    }
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isDragging]);

  const handleMouseDown = (e) => {
    if (tutorialWidgetRef.current) {
      const rect = tutorialWidgetRef.current.getBoundingClientRect();
      dragOffset.current = {
        x: e.clientX - rect.left,
        y: e.clientY - rect.top
      };
      setIsDragging(true);
    }
  };

  //Lógica del tutorial
  const startTutorial = () => {
    setTutorialMode(true);
    setCurrentStep(0);
    setStepComplete(false);
    setShowIntro(false);
    setRules([]);
    setDefaultPolicy('ACCEPT');
    setStats({ total: 0, allowed: 0, blocked: 0, attackAttempts: 0, statefulMatches: 0 });
    setLogs([]);
    setIsRunning(false);
    setIsStateful(false);
    setIsAutoDefense(false);
    setActiveTab('dashboard');
  };

  const skipTutorial = () => {
    setTutorialMode(false);
    setShowIntro(false);
  };

  useEffect(() => {
    if (!tutorialMode || stepComplete || currentStep >= TUTORIAL_STEPS.length) return;

    const step = TUTORIAL_STEPS[currentStep];
    if (!step) return;

    const currentState = {
      defaultPolicy,
      rules,
      activeTab,
      stats,
      isRunning,
      isStateful,
      attackMode,
      selectedPacket
    };

    if (step.actionCheck(currentState)) {
      setStepComplete(true);
    }
  }, [tutorialMode, stepComplete, currentStep, defaultPolicy, rules, activeTab, stats, isRunning, isStateful, attackMode, selectedPacket]);

  useEffect(() => {
    if (stepComplete) {
      if (currentStep !== 0) {
        setShowTutorialSuccess(true);
        setTimeout(() => setShowTutorialSuccess(false), 2000);
      }

      const delay = currentStep === 0 ? 0 : 2500;
      const timer = setTimeout(() => {
        setCurrentStep(prev => {
          const next = prev + 1;
          return next < TUTORIAL_STEPS.length ? next : prev;
        });
        setStepComplete(false);
      }, delay);

      return () => clearTimeout(timer);
    }
  }, [stepComplete]);

  //Lógica de Auto-Defensa (IPS)
  const autoBlock = (type, value) => {
    setRules(prevRules => {
      // Evitar duplicados
      const exists = prevRules.some(r =>
        r.action === 'DROP' &&
        ((type === 'IP' && r.sourceIP === value) || (type === 'PORT' && r.port === value.toString()))
      );
      if (exists) return prevRules;

      const newAutoRule = {
        id: Date.now(),
        name: `[IPS] Auto-Block ${type} ${value}`,
        sourceIP: type === 'IP' ? value : '*',
        destIP: '*',
        protocol: '*',
        port: type === 'PORT' ? value.toString() : '*',
        action: 'DROP',
        expiresAt: Date.now() + BAN_DURATION,
        content: ''
      };

      return [newAutoRule, ...prevRules]; // Añadir al principio (mayor prioridad)
    });
  };

  // Efecto para análisis periódico de tráfico (cada 1s)
  useEffect(() => {
    if (!isRunning || !isAutoDefense) return;

    const analysisInterval = setInterval(() => {
      const analysis = trafficAnalysisRef.current;

      // Analizar IPs
      Object.entries(analysis.ips).forEach(([ip, count]) => {
        if (count > 3) {
          autoBlock('IP', ip);
        }
      });

      // Analizar Puertos
      Object.entries(analysis.ports).forEach(([port, count]) => {
        if (count > 8) {
          autoBlock('PORT', port);
        }
      });

      trafficAnalysisRef.current = { ips: {}, ports: {} };
    }, 1000);

    return () => clearInterval(analysisInterval);
  }, [isRunning, isAutoDefense]);


  //Motor del Firewall

  const intervalRef = useRef(null);
  const connectionTimerRef = useRef(null);

  const checkMatch = (packetValue, ruleValue) => {
    if (ruleValue === '*' || ruleValue === '') return true;
    return packetValue.toString().toLowerCase() === ruleValue.toString().toLowerCase();
  };

  const checkContentMatch = (packetPayload, ruleContent) => {
    if (!ruleContent || ruleContent === '*') return true;
    return packetPayload && packetPayload.includes(ruleContent);
  };

  const processPacket = (packet) => {
    const { rules, defaultPolicy, isStateful, connections, isAutoDefense } = stateRef.current;

    // IPS: Actualizar contadores de tráfico
    if (isAutoDefense) {
      const analysis = trafficAnalysisRef.current;
      analysis.ips[packet.sourceIP] = (analysis.ips[packet.sourceIP] || 0) + 1;
      analysis.ports[packet.destPort] = (analysis.ports[packet.destPort] || 0) + 1;
    }

    let actionTaken = defaultPolicy;
    let matchedRuleName = 'Política por Defecto';
    let isStatefulMatch = false;
    let matchedRuleIndex = -1;

    if (isStateful) {
      const existingConn = connections.find(c =>
        c.protocol === packet.protocol &&
        ((c.sourceIP === packet.sourceIP && c.destIP === packet.destIP && c.srcPort === packet.srcPort && c.destPort === packet.destPort) ||
          (c.sourceIP === packet.destIP && c.destIP === packet.sourceIP && c.srcPort === packet.destPort && c.destPort === packet.srcPort))
      );
      if (existingConn) {
        actionTaken = 'ACCEPT';
        matchedRuleName = 'Stateful Inspection (Conexión Activa)';
        isStatefulMatch = true;
        setConnections(prev => prev.map(c => c.id === existingConn.id ? { ...c, ttl: 15 } : c));
      }
    }

    if (!isStatefulMatch) {
      for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        if (
          checkMatch(packet.sourceIP, rule.sourceIP) &&
          checkMatch(packet.destIP, rule.destIP) &&
          checkMatch(packet.protocol, rule.protocol) &&
          checkMatch(packet.destPort, rule.port) &&
          checkContentMatch(packet.payload, rule.content)
        ) {
          actionTaken = rule.action;
          matchedRuleName = rule.name;
          matchedRuleIndex = i;
          break;
        }
      }
    }

    // Calculo de Carga de CPU Simulada
    let loadImpact = 0;
    if (stateRef.current.attackMode !== ATTACK_TYPES.NONE) {
      // Ataque activo
      if (matchedRuleIndex !== -1 && actionTaken === 'DROP') {
        // Bloqueado por regla explícita: Carga baja
        loadImpact = 20 + (matchedRuleIndex * 2);
      } else {
        // Pasa hasta el final o es aceptado: Carga alta
        loadImpact = 95;
      }
    } else {
      // Tráfico normal
      loadImpact = 5 + (Math.random() * 10);
    }
    setSystemLoad(prev => Math.floor((prev * 0.7) + (loadImpact * 0.3)));

    if (isStateful && actionTaken === 'ACCEPT' && !isStatefulMatch && !packet.isReturnTraffic && packet.flags.includes('SYN')) {
      const newConn = {
        id: Date.now() + Math.random(),
        sourceIP: packet.sourceIP, destIP: packet.destIP,
        srcPort: packet.srcPort, destPort: packet.destPort,
        protocol: packet.protocol, ttl: 15, startTime: new Date().toLocaleTimeString(),
        sourceMAC: packet.sourceMAC
      };
      setConnections(prev => [...prev, newConn]);
    }

    setLogs(prev => [{ ...packet, action: actionTaken, ruleName: matchedRuleName, isStatefulMatch }, ...prev].slice(0, 100));
    setStats(prev => ({
      total: prev.total + 1,
      allowed: actionTaken === 'ACCEPT' ? prev.allowed + 1 : prev.allowed,
      blocked: actionTaken === 'DROP' ? prev.blocked + 1 : prev.blocked,
      attackAttempts: packet.isAttackSignature ? prev.attackAttempts + 1 : prev.attackAttempts,
      statefulMatches: isStatefulMatch ? prev.statefulMatches + 1 : prev.statefulMatches
    }));
  };

  useEffect(() => {
    if (isRunning) {
      let speed = 1000;
      if (stateRef.current.attackMode === ATTACK_TYPES.DDoS_UDP || stateRef.current.attackMode === ATTACK_TYPES.SYN_FLOOD) {
        speed = 20;
      } else if (stateRef.current.attackMode === ATTACK_TYPES.SQL_INJECTION) {
        speed = 800;
      }

      clearInterval(intervalRef.current);
      intervalRef.current = setInterval(() => {
        const { connections, attackMode } = stateRef.current;
        processPacket(generatePacket(connections, attackMode));
      }, speed);
    } else {
      clearInterval(intervalRef.current);
      setSystemLoad(0);
    }
    return () => clearInterval(intervalRef.current);
  }, [isRunning, attackMode]);

  useEffect(() => {
    if (isRunning && isStateful) {
      connectionTimerRef.current = setInterval(() => {
        setConnections(prev => prev.map(c => ({ ...c, ttl: c.ttl - 1 })).filter(c => c.ttl > 0));
      }, 1000);
    }
    return () => clearInterval(connectionTimerRef.current);
  }, [isRunning, isStateful]);

  //Manejadores de UI
  const handleAddRule = () => {
    if (!newRule.name) return alert("Nombre de regla requerido");
    setRules([...rules, { ...newRule, id: Date.now() }]);
    setNewRule({ name: '', sourceIP: '*', destIP: '*', protocol: 'TCP', port: '*', action: 'ACCEPT', content: '' });
  };

  const handleDeleteRule = (id) => setRules(rules.filter(r => r.id !== id));

  const moveRule = (index, direction) => {
    const newRules = [...rules];
    if (direction === 'up' && index > 0) {
      [newRules[index], newRules[index - 1]] = [newRules[index - 1], newRules[index]];
    } else if (direction === 'down' && index < rules.length - 1) {
      [newRules[index], newRules[index + 1]] = [newRules[index + 1], newRules[index]];
    }
    setRules(newRules);
  };

  const handleSaveConfig = (e) => {
    if (e) e.preventDefault();
    const config = {
      rules,
      defaultPolicy,
      isStateful,
      isAutoDefense
    };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(config, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "firewall_scenario.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  const handleLoadConfig = (event) => {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const config = JSON.parse(e.target.result);
        if (config.rules) setRules(config.rules);
        if (config.defaultPolicy) setDefaultPolicy(config.defaultPolicy);
        if (config.isStateful !== undefined) setIsStateful(config.isStateful);
        if (config.isAutoDefense !== undefined) setIsAutoDefense(config.isAutoDefense);
        alert("Escenario cargado correctamente.");
      } catch (err) {
        console.error("Error parsing JSON", err);
        alert("Archivo de configuración inválido");
      }
    };
    reader.readAsText(file);
    event.target.value = null;
  };

  const handleManualInject = () => {
    const pkt = {
      ...manualPacket,
      id: Date.now(),
      timestamp: new Date().toLocaleTimeString(),
      sourceMAC: generateMAC(),
      destMAC: SERVER_MAC,
      isAttackSignature: false,
      flags: 'PSH',
      isReturnTraffic: false,
      ttl: 64,
      id_ip: 0xDEAD,
      seq_num: 12345,
      ack_num: 0,
      window_size: 65535,
      checksum: 'MANUAL',
      srcPort: 5555
    };
    processPacket(pkt);
  };

  const toggleAttack = (type) => {
    if (attackMode === type) {
      setAttackMode(ATTACK_TYPES.NONE);
      setIsRunning(false);
    } else {
      setAttackMode(type);
      setIsRunning(true);
    }
  };

  const downloadCSV = () => {
    const headers = ["Hora", "IP Origen", "IP Destino", "Proto", "Puerto", "Payload", "Acción", "Regla"];
    const rows = logs.map(l => [l.timestamp, l.sourceIP, l.destIP, l.protocol, l.destPort, `"${l.payload}"`, l.action, l.ruleName]);
    const csvContent = "data:text/csv;charset=utf-8," + headers.join(",") + "\n" + rows.map(e => e.join(",")).join("\n");
    const link = document.createElement("a");
    link.href = encodeURI(csvContent);
    link.download = "firewall_logs.csv";
    link.click();
  };

  const StatCard = ({ title, value, color, icon: Icon, tooltip }) => (
    <div className={`p-4 rounded-lg shadow border flex items-center justify-between ${darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-gray-200'}`}>
      <div>
        <div className={`text-sm font-medium flex items-center ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
          {title}
          {tooltip && <EduTooltip text={tooltip} />}
        </div>
        <p className={`text-2xl font-bold ${color}`}>{value}</p>
      </div>
      <div className={`p-3 rounded-full bg-opacity-10 ${color.replace('text-', 'bg-')}`}>
        <Icon className={`w-6 h-6 ${color}`} />
      </div>
    </div>
  );

  const Badge = ({ type }) => {
    const styles = type === 'ACCEPT'
      ? (darkMode ? 'bg-green-900/30 text-green-400 border-green-900' : 'bg-green-100 text-green-800 border-green-200')
      : (darkMode ? 'bg-red-900/30 text-red-400 border-red-900' : 'bg-red-100 text-red-800 border-red-200');
    return <span className={`px-2 py-1 rounded text-xs font-bold border ${styles}`}>{type}</span>;
  };

  const currentTutorialStepData = TUTORIAL_STEPS[currentStep] || TUTORIAL_STEPS[0];

  return (
    <div className={`min-h-screen font-sans relative pb-32 transition-colors duration-300 ${darkMode ? 'bg-slate-950 text-gray-100' : 'bg-gray-50 text-gray-800'}`}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Source+Code+Pro:wght@400;600;700&display=swap');
        
        :root {
          --font-ui: 'Share Tech Mono', monospace;
          --font-code: 'Source Code Pro', monospace;
        }

        /* Override Tailwind defaults for this component */
        .font-sans, body { font-family: var(--font-ui) !important; }
        .font-mono { font-family: var(--font-code) !important; }
        
        /* Ensure inputs and buttons also use the font */
        input, button, select, textarea { font-family: var(--font-ui) !important; }
      `}</style>

      <PacketInspector packet={selectedPacket} onClose={() => setSelectedPacket(null)} darkMode={darkMode} />

      {tutorialMode && (
        <div
          ref={tutorialWidgetRef}
          className={`fixed z-[70] w-96 animate-fade-in-up ${tutorialPosition ? '' : 'bottom-6 right-6'}`}
          style={tutorialPosition ? { left: tutorialPosition.x, top: tutorialPosition.y } : {}}
        >
          {showTutorialSuccess && (
            <div className="absolute -top-16 left-0 right-0 bg-green-500 text-white p-2 rounded-lg shadow-lg text-center font-bold animate-bounce pointer-events-none">
              ¡Objetivo Completado!
            </div>
          )}

          <div className="bg-slate-900 rounded-xl shadow-2xl border-2 border-blue-500 overflow-hidden text-white">
            <div
              className="bg-gradient-to-r from-blue-600 to-blue-800 p-3 flex justify-between items-center cursor-move select-none"
              onMouseDown={handleMouseDown}
            >
              <div className="flex items-center gap-2 font-bold">
                <Move className="w-4 h-4 text-blue-200" />
                Paso {currentStep} de {TUTORIAL_STEPS.length - 1}
              </div>
              <button onClick={skipTutorial} className="text-blue-200 hover:text-white text-xs underline">Salir</button>
            </div>
            <div className="p-5">
              <h3 className="text-lg font-bold mb-2 text-blue-300">
                {currentTutorialStepData?.title}
              </h3>
              <p className="text-sm text-gray-300 mb-4 leading-relaxed">
                {currentTutorialStepData?.content}
              </p>

              {currentTutorialStepData?.hint && (
                <div className="bg-slate-800 p-2 rounded border border-slate-700 text-xs text-gray-400 italic mb-4">
                  Pista: {currentTutorialStepData.hint}
                </div>
              )}

              <div className="flex justify-end">
                {currentStep === 0 ? (
                  <button onClick={() => setCurrentStep(1)} className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded text-sm font-bold flex items-center gap-2">
                    Comenzar <ChevronRight className="w-4 h-4" />
                  </button>
                ) : currentStep === TUTORIAL_STEPS.length - 1 ? (
                  <button onClick={skipTutorial} className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded text-sm font-bold">
                    Finalizar Entrenamiento
                  </button>
                ) : (
                  <div className="text-xs font-mono text-yellow-400 animate-pulse">
                    Esperando acción del usuario...
                  </div>
                )}
              </div>
            </div>
            <div className="h-1 bg-slate-800 w-full">
              <div
                className="h-full bg-green-500 transition-all duration-500"
                style={{ width: `${(currentStep / (TUTORIAL_STEPS.length - 1)) * 100}%` }}
              />
            </div>
          </div>
        </div>
      )}

      {showIntro && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900 bg-opacity-90 backdrop-blur-sm p-4">
          <div className={`rounded-xl shadow-2xl max-w-4xl w-full overflow-hidden animate-fade-in-up ${darkMode ? 'bg-slate-900 border border-slate-700' : 'bg-white'}`}>
            <div className="bg-slate-900 p-6 text-white flex justify-between items-center">
              <div className="flex items-center gap-3">
                <Shield className="w-8 h-8 text-blue-400" />
                <h2 className="text-2xl font-bold">Bienvenido a Firewall Playground</h2>
              </div>
            </div>
            <div className="p-8">
              <p className={`text-lg mb-8 leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                Elige un modo para comenzar
              </p>
              <div className="grid md:grid-cols-2 gap-6">
                <button
                  onClick={startTutorial}
                  className={`group relative p-6 rounded-xl border-2 transition-all text-left ${darkMode ? 'bg-blue-900/20 border-blue-800 hover:border-blue-500' : 'bg-blue-50 border-blue-100 hover:border-blue-500 hover:shadow-lg'}`}
                >
                  <div className="bg-blue-600 w-12 h-12 rounded-full flex items-center justify-center mb-4 text-white group-hover:scale-110 transition-transform">
                    <GraduationCap className="w-6 h-6" />
                  </div>
                  <h3 className={`text-xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-800'}`}>Modo Entrenamiento</h3>
                  <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    Recomendado para principiantes. Un tutorial guiado paso a paso donde aprenderás a configurar reglas básicas y proteger el servidor desde cero.
                  </p>
                </button>

                <button
                  onClick={skipTutorial}
                  className={`group relative p-6 rounded-xl border-2 transition-all text-left ${darkMode ? 'bg-slate-800 border-slate-700 hover:border-gray-400' : 'bg-white border-gray-100 hover:border-gray-400 hover:shadow-lg'}`}
                >
                  <div className="bg-gray-700 w-12 h-12 rounded-full flex items-center justify-center mb-4 text-white group-hover:scale-110 transition-transform">
                    <Activity className="w-6 h-6" />
                  </div>
                  <h3 className={`text-xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-800'}`}>Modo Libre</h3>
                  <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    Acceso total al simulador con una configuración predeterminada. Experimenta con ataques, reglas DPI y stateful inspection a tu ritmo.
                  </p>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="bg-slate-900 text-white p-4 shadow-lg sticky top-0 z-40">
        <div className="container mx-auto flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-3">
            <img src={logo} alt="Logo" className="h-[70px] w-auto object-contain" />
            <div>
              <h1 className="text-xl font-bold tracking-wide flex items-center gap-2">
                FireWall Playground {tutorialMode && <span className="bg-blue-600 text-[10px] px-2 py-0.5 rounded text-white uppercase tracking-wider">Modo Entrenamiento</span>}
                <span className="text-xs font-normal opacity-70 border border-slate-600 px-1 rounded bg-slate-800 ml-2">by Alejandro Aisa</span>
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Botón MODO OSCURO */}
            <button
              onClick={() => setDarkMode(!darkMode)}
              className="p-2 rounded-lg bg-slate-800 border border-slate-700 hover:bg-slate-700 transition-colors text-yellow-400 cursor-pointer"
              title={darkMode ? "Cambiar a Modo Claro" : "Cambiar a Modo Oscuro"}
            >
              {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>

            <div className="h-8 w-px bg-slate-700 mx-2 hidden md:block"></div>

            {/* Boton Auto Defense (IPS) */}
            <div className={`flex items-center gap-3 p-2 rounded-lg border transition-colors ${isAutoDefense ? 'bg-orange-900 border-orange-500' : 'bg-slate-800 border-slate-700'}`}>
              <span className={`text-xs font-bold flex items-center gap-1 ${isAutoDefense ? 'text-orange-200' : 'text-gray-300'}`}>
                <Siren className="w-3 h-3" /> IPS Mode
                <EduTooltip side="bottom" text="Sistema de Prevención de Intrusiones. Analiza frecuencia de paquetes y bloquea automáticamente IPs abusivas o ataques DDoS." />
              </span>
              <button
                onClick={() => setIsAutoDefense(!isAutoDefense)}
                disabled={tutorialMode}
                className={`relative w-12 h-6 rounded-full transition-colors duration-200 ease-in-out focus:outline-none ${isAutoDefense ? 'bg-orange-500' : 'bg-gray-600'} ${tutorialMode ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <span className={`absolute left-1 top-1 w-4 h-4 bg-white rounded-full transition-transform duration-200 ease-in-out ${isAutoDefense ? 'translate-x-6' : 'translate-x-0'}`} />
              </button>
            </div>

            <div className="h-8 w-px bg-slate-700 mx-2 hidden md:block"></div>

            <div className="flex items-center gap-3 bg-slate-800 p-2 rounded-lg border border-slate-700">
              <span className="text-xs font-bold text-gray-300 flex items-center gap-1">
                Modo Stateful
                <EduTooltip side="bottom" text="Si está activo, el firewall recuerda las conexiones salientes y permite sus respuestas automáticamente sin reglas adicionales." />
              </span>
              <button
                onClick={() => setIsStateful(!isStateful)}
                disabled={tutorialMode && currentStep < 3}
                className={`relative w-12 h-6 rounded-full transition-colors duration-200 ease-in-out focus:outline-none ${isStateful ? 'bg-blue-500' : 'bg-gray-600'} ${tutorialMode && currentStep < 3 ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <span className={`absolute left-1 top-1 w-4 h-4 bg-white rounded-full transition-transform duration-200 ease-in-out ${isStateful ? 'translate-x-6' : 'translate-x-0'}`} />
              </button>
            </div>

            <div className="h-8 w-px bg-slate-700 mx-2 hidden md:block"></div>

            <div className="flex items-center gap-2 bg-slate-800 p-1 rounded-full border border-slate-700">
              <div className="flex items-center gap-2 px-3">
                <span className="text-xs text-gray-400">Estado:</span>
                {attackMode !== ATTACK_TYPES.NONE ? (
                  <span className="flex items-center gap-1 text-red-400 text-sm font-bold animate-pulse">
                    <AlertTriangle className="w-4 h-4" /> ¡ATAQUE!
                  </span>
                ) : isRunning ? (
                  <span className="flex items-center gap-1 text-green-400 text-sm font-bold">
                    <Activity className="w-4 h-4 animate-pulse" /> Activo
                  </span>
                ) : (
                  <span className="text-gray-400 text-sm">Detenido</span>
                )}
              </div>

              <button
                onClick={() => setIsRunning(!isRunning)}
                className={`flex items-center gap-2 px-4 py-1.5 rounded-full font-bold transition-colors text-xs shadow-sm ${isRunning ? 'bg-red-500 hover:bg-red-600 text-white' : 'bg-green-500 hover:bg-green-600 text-white'}`}
              >
                {isRunning ? <><Pause className="w-3 h-3" /> Detener</> : <><Play className="w-3 h-3" /> Iniciar</>}
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="container mx-auto p-4 mt-4">

        {/* Tabs */}
        <div className={`flex gap-2 mb-6 border-b overflow-x-auto pb-1 ${darkMode ? 'border-slate-700' : 'border-gray-200'}`}>
          {[
            { id: 'dashboard', label: 'Dashboard', icon: Activity },
            { id: 'rules', label: 'Reglas & DPI', icon: Settings },
            { id: 'state', label: `Tabla de Estados (${connections.length})`, icon: RefreshCw },
            { id: 'logs', label: 'Logs en Vivo', icon: FileText },
            { id: 'simulate', label: 'Simulador de Ataques', icon: Zap },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 md:px-6 py-3 font-medium transition-colors border-b-2 whitespace-nowrap relative ${activeTab === tab.id
                ? (darkMode ? 'border-blue-500 text-blue-400 bg-blue-900/20' : 'border-blue-600 text-blue-600 bg-blue-50')
                : (darkMode ? 'border-transparent text-gray-400 hover:text-gray-200 hover:bg-slate-800' : 'border-transparent text-gray-500 hover:text-gray-700 hover:bg-gray-100')
                }`}
            >
              <tab.icon className="w-4 h-4" /> {tab.label}
              {tutorialMode && TUTORIAL_STEPS[currentStep].tab === tab.id && (
                <span className="w-2 h-2 rounded-full bg-blue-600 animate-ping absolute top-2 right-2" />
              )}
            </button>
          ))}
        </div>

        {/* VISTA: Dashboard */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* System Load */}
            <div className={`p-4 rounded-lg shadow border flex flex-col gap-2 ${darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-gray-200'}`}>
              <div className="flex justify-between items-center">
                <h3 className={`text-sm font-bold flex items-center gap-2 ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                  <Cpu className="w-4 h-4" /> Carga del Sistema (CPU Load)
                  <EduTooltip text="Indica cuánto esfuerzo está haciendo el firewall. Si llega al 100%, el sistema colapsa. Las reglas 'DROP' explícitas al inicio reducen la carga. La política por defecto consume más CPU." />
                </h3>
                <span className={`text-sm font-bold ${systemLoad > 90 ? 'text-red-600 animate-pulse' : (darkMode ? 'text-gray-300' : 'text-gray-600')}`}>{systemLoad}%</span>
              </div>
              <div className={`w-full rounded-full h-4 overflow-hidden ${darkMode ? 'bg-slate-700' : 'bg-gray-200'}`}>
                <div
                  className={`h-full transition-all duration-300 ${systemLoad > 90 ? 'bg-red-600' : systemLoad > 60 ? 'bg-yellow-500' : 'bg-green-500'}`}
                  style={{ width: `${systemLoad}%` }}
                ></div>
              </div>
              {systemLoad > 90 && <p className="text-xs text-red-600 font-bold mt-1">PELIGRO: Carga crítica. Activa el IPS o crea reglas de bloqueo explícitas.</p>}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <StatCard title="Paquetes Totales" value={stats.total} color="text-blue-600" icon={Activity} />
              <StatCard title="Permitidos (ACCEPT)" value={stats.allowed} color="text-green-600" icon={Shield} />
              <StatCard title="Bloqueados (DROP)" value={stats.blocked} color="text-red-600" icon={AlertTriangle} />
              <StatCard
                title="Intentos de Ataque"
                value={stats.attackAttempts}
                color="text-orange-600"
                icon={Zap}
                tooltip="Paquetes que coinciden con firmas de ataque conocidas (SQLi, DDoS, etc)."
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className={`p-6 rounded-lg shadow border ${darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-gray-200'}`}>
                <h3 className={`text-lg font-bold mb-4 ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>Top IPs de Origen (Recientes)</h3>
                <div className="space-y-2">
                  {Object.entries(logs.reduce((acc, log) => {
                    acc[log.sourceIP] = (acc[log.sourceIP] || 0) + 1;
                    return acc;
                  }, {}))
                    .sort(([, a], [, b]) => b - a)
                    .slice(0, 5)
                    .map(([ip, count], idx) => (
                      <div key={ip} className={`flex justify-between items-center p-2 rounded ${darkMode ? 'bg-slate-800' : 'bg-gray-50'}`}>
                        <div className="flex items-center gap-2">
                          <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${darkMode ? 'bg-blue-900 text-blue-300' : 'bg-blue-100 text-blue-600'}`}>{idx + 1}</span>
                          <span className="font-mono text-sm">{ip}</span>
                        </div>
                        <span className={`text-xs font-bold px-2 py-1 rounded ${darkMode ? 'bg-slate-700 text-gray-300' : 'bg-gray-200 text-gray-600'}`}>{count} pkt</span>
                      </div>
                    ))}
                  {logs.length === 0 && <p className="text-gray-400 italic text-center">Sin datos. Inicia la simulación.</p>}
                </div>
              </div>

              {/* LISTA DE BLOQUEOS IPS */}
              <div className={`p-6 rounded-lg shadow border ${darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-gray-200'}`}>
                <h3 className={`text-lg font-bold mb-4 flex items-center gap-2 ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>
                  <Siren className="w-5 h-5 text-red-600" />
                  Bloqueos Activos IPS (TTL 10s)
                </h3>
                <div className="space-y-2 overflow-y-auto max-h-64">
                  {rules.filter(r => r.name.startsWith('[IPS]')).length > 0 ? (
                    rules.filter(r => r.name.startsWith('[IPS]')).map(rule => {
                      const remaining = Math.max(0, Math.ceil((rule.expiresAt - timeNow) / 1000));
                      return (
                        <div key={rule.id} className={`flex justify-between items-center p-2 rounded text-xs animate-fade-in ${darkMode ? 'bg-red-900/20 border border-red-900' : 'bg-red-50 border border-red-100'}`}>
                          <div className="flex items-center gap-2">
                            <Shield className="w-3 h-3 text-red-600" />
                            <div>
                              <span className={`font-bold block ${darkMode ? 'text-red-300' : 'text-red-800'}`}>{rule.name.replace('[IPS] Auto-Block ', '')}</span>
                              <span className="text-[10px] text-red-400">Expiración automática</span>
                            </div>
                          </div>
                          <div className="flex flex-col items-end">
                            <span className={`font-mono font-bold ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{remaining}s</span>
                            <div className={`w-16 rounded-full h-1 mt-1 ${darkMode ? 'bg-red-900' : 'bg-red-200'}`}>
                              <div className="bg-red-600 h-1 rounded-full transition-all duration-1000" style={{ width: `${(remaining / 10) * 100}%` }}></div>
                            </div>
                          </div>
                        </div>
                      );
                    })
                  ) : (
                    <div className="text-center py-8 text-gray-400 italic">
                      <Shield className="w-8 h-8 mx-auto mb-2 opacity-20" />
                      <p>Sin bloqueos automáticos activos</p>
                      <p className="text-[10px] mt-1">Activa el modo IPS y genera tráfico malicioso.</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* VISTA: Reglas */}
        {activeTab === 'rules' && (
          <div className="space-y-6">
            <div className={`p-6 rounded-lg shadow border transition-all duration-300 ${darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-gray-200'} ${tutorialMode && currentStep === 1 ? 'border-blue-500 ring-2 ring-blue-200' : ''}`}>

              {/* HEADER: Política por defecto + Gestión de Escenarios */}
              <div className={`flex flex-col md:flex-row justify-between items-start md:items-center mb-6 pb-4 border-b gap-4 ${darkMode ? 'border-slate-700' : 'border-gray-200'}`}>
                <div>
                  <h3 className={`text-lg font-bold flex items-center ${darkMode ? 'text-white' : 'text-gray-800'}`}>
                    Gestión de Reglas
                  </h3>
                  <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Define el comportamiento y guarda tus escenarios.</p>
                </div>

                <div className="flex flex-col md:flex-row items-end md:items-center gap-4">
                  {/* Botones de Guardar/Cargar */}
                  <div className="flex gap-2">
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleLoadConfig}
                      className="hidden"
                      accept=".json"
                    />
                    <button
                      type="button"
                      onClick={() => fileInputRef.current.click()}
                      className={`flex items-center gap-1 px-3 py-1.5 rounded text-xs font-bold transition-colors border ${darkMode ? 'bg-slate-800 border-slate-600 text-gray-300 hover:bg-slate-700' : 'bg-gray-100 hover:bg-gray-200 text-gray-700 border-gray-300'}`}
                    >
                      <Upload size={14} /> Cargar
                    </button>
                    <button
                      type="button"
                      onClick={handleSaveConfig}
                      className={`flex items-center gap-1 px-3 py-1.5 rounded text-xs font-bold transition-colors border ${darkMode ? 'bg-blue-900/30 border-blue-800 text-blue-300 hover:bg-blue-900/50' : 'bg-blue-50 hover:bg-blue-100 text-blue-700 border-blue-200'}`}
                    >
                      <Save size={14} /> Guardar
                    </button>
                  </div>

                  <div className="w-px h-8 bg-gray-300 hidden md:block"></div>

                  {/* Política por Defecto */}
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-bold uppercase ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Política Default:</span>
                    <div className={`flex items-center p-1 rounded-lg ${darkMode ? 'bg-slate-800' : 'bg-gray-100'}`}>
                      {ACTIONS.map(action => (
                        <button
                          key={action}
                          onClick={() => setDefaultPolicy(action)}
                          className={`px-3 py-1 rounded-md text-xs font-bold transition-colors ${defaultPolicy === action
                            ? (action === 'ACCEPT' ? 'bg-green-500 text-white' : 'bg-red-500 text-white')
                            : (darkMode ? 'text-gray-400 hover:bg-slate-700' : 'text-gray-500 hover:bg-gray-200')
                            }`}
                        >
                          {action}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className={`${darkMode ? 'bg-slate-800 text-gray-300' : 'bg-gray-100 text-gray-600'} uppercase`}>
                    <tr>
                      <th className="p-3 w-16">
                        <div className="flex items-center">
                          #
                          <EduTooltip align="left" side="bottom" text="Orden de Evaluación: El firewall lee las reglas de ARRIBA a ABAJO. La primera que coincida gana." />
                        </div>
                      </th>
                      <th className="p-3">Nombre Regla</th>
                      <th className="p-3">Origen</th>
                      <th className="p-3">Proto</th>
                      <th className="p-3">Puerto</th>
                      <th className="p-3">Contenido (DPI)</th>
                      <th className="p-3">Acción</th>
                      <th className="p-3 text-right">Control</th>
                    </tr>
                  </thead>
                  <tbody className={`divide-y ${darkMode ? 'divide-slate-800' : 'divide-gray-100'}`}>
                    {rules.map((rule, index) => (
                      <tr key={rule.id} className={`${darkMode ? 'hover:bg-slate-800' : 'hover:bg-gray-50'}`}>
                        <td className="p-3 font-bold text-gray-400">{index + 1}</td>
                        <td className="p-3 font-medium">
                          {rule.name.startsWith('[IPS]') ?
                            <div className="flex flex-col">
                              <span className="flex items-center gap-1 text-orange-600"><Siren className="w-3 h-3" /> {rule.name}</span>
                              <span className="text-[9px] text-gray-400 flex items-center gap-1">
                                <Clock className="w-3 h-3" /> Expira en {Math.max(0, Math.ceil((rule.expiresAt - timeNow) / 1000))}s
                              </span>
                            </div>
                            : rule.name
                          }
                        </td>
                        <td className="p-3 font-mono text-xs">{rule.sourceIP}</td>
                        <td className="p-3">{rule.protocol}</td>
                        <td className="p-3 font-mono">{rule.port}</td>
                        <td className="p-3 font-mono text-xs text-orange-600 truncate max-w-[100px]">{rule.content || '*'}</td>
                        <td className="p-3"><Badge type={rule.action} /></td>
                        <td className="p-3 flex justify-end gap-1">
                          <button onClick={() => moveRule(index, 'up')} disabled={index === 0} className="p-1 text-gray-400 hover:text-blue-600 disabled:opacity-30"><ArrowUp className="w-4 h-4" /></button>
                          <button onClick={() => moveRule(index, 'down')} disabled={index === rules.length - 1} className="p-1 text-gray-400 hover:text-blue-600 disabled:opacity-30"><ArrowDown className="w-4 h-4" /></button>
                          <button onClick={() => handleDeleteRule(rule.id)} className="p-1 text-gray-400 hover:text-red-600"><Trash2 className="w-4 h-4" /></button>
                        </td>
                      </tr>
                    ))}
                    {rules.length === 0 && (
                      <tr><td colSpan="8" className="p-4 text-center text-gray-400 italic">No hay reglas definidas. Se aplicará la política por defecto.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div className={`p-6 rounded-lg border transition-all duration-300 ${darkMode ? 'bg-blue-900/10 border-blue-900' : 'bg-blue-50 border-blue-100'} ${tutorialMode && (currentStep === 2 || currentStep === 6 || currentStep === 7) ? 'border-blue-500 ring-4 ring-blue-100' : ''}`}>
              <h3 className={`text-md font-bold mb-4 flex items-center gap-2 ${darkMode ? 'text-blue-300' : 'text-blue-800'}`}>
                <Plus className="w-4 h-4" /> Añadir Nueva Regla
                <EduTooltip text="Define los criterios específicos. Un asterisco (*) significa 'cualquiera'. Usa 'Contenido' para filtrar payloads específicos." />
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-8 gap-2 items-end">
                <div className="md:col-span-2">
                  <label className={`block text-xs font-bold mb-1 ${darkMode ? 'text-blue-300' : 'text-blue-800'}`}>Nombre</label>
                  <input type="text" placeholder="Ej: Bloquear SQL" className={`w-full p-2 border rounded text-sm ${darkMode ? 'bg-slate-800 border-slate-600 text-white' : ''}`} value={newRule.name} onChange={e => setNewRule({ ...newRule, name: e.target.value })} />
                </div>
                <div>
                  <label className={`block text-xs font-bold mb-1 ${darkMode ? 'text-blue-300' : 'text-blue-800'}`}>IP Origen</label>
                  <input type="text" placeholder="*" className={`w-full p-2 border rounded text-sm font-mono ${darkMode ? 'bg-slate-800 border-slate-600 text-white' : ''}`} value={newRule.sourceIP} onChange={e => setNewRule({ ...newRule, sourceIP: e.target.value })} />
                </div>
                <div>
                  <label className={`block text-xs font-bold mb-1 ${darkMode ? 'text-blue-300' : 'text-blue-800'}`}>Proto</label>
                  <select className={`w-full p-2 border rounded text-sm ${darkMode ? 'bg-slate-800 border-slate-600 text-white' : ''}`} value={newRule.protocol} onChange={e => setNewRule({ ...newRule, protocol: e.target.value })}>
                    <option value="*">Todos</option>
                    {PROTOCOLS.map(p => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <label className={`block text-xs font-bold mb-1 ${darkMode ? 'text-blue-300' : 'text-blue-800'}`}>Puerto</label>
                  <input type="text" placeholder="*" className={`w-full p-2 border rounded text-sm font-mono ${darkMode ? 'bg-slate-800 border-slate-600 text-white' : ''}`} value={newRule.port} onChange={e => setNewRule({ ...newRule, port: e.target.value })} />
                </div>
                <div className="md:col-span-2">
                  <label className={`block text-xs font-bold mb-1 flex items-center gap-1 ${darkMode ? 'text-blue-300' : 'text-blue-800'}`}>
                    Contenido (DPI)
                    <EduTooltip text="Inspección Profunda de Paquetes. Escribe una palabra clave (ej: 'SELECT') para bloquear paquetes que la contengan." />
                  </label>
                  <input type="text" placeholder="Ej: DROP TABLE" className={`w-full p-2 border rounded text-sm font-mono ${darkMode ? 'bg-slate-800 border-orange-900 text-orange-200' : 'border-orange-200 bg-orange-50'}`} value={newRule.content} onChange={e => setNewRule({ ...newRule, content: e.target.value })} />
                </div>
                <div>
                  <label className={`block text-xs font-bold mb-1 ${darkMode ? 'text-blue-300' : 'text-blue-800'}`}>Acción</label>
                  <select className={`w-full p-2 border rounded text-sm font-bold ${darkMode ? 'bg-slate-800 border-slate-600 text-white' : ''}`} value={newRule.action} onChange={e => setNewRule({ ...newRule, action: e.target.value })}>
                    {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
                  </select>
                </div>
                <div className="md:col-span-8 mt-2">
                  <button onClick={handleAddRule} className="w-full bg-blue-600 text-white p-2 rounded shadow hover:bg-blue-700 font-bold text-sm">Añadir Regla</button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* VISTA: Tabla de Estados */}
        {activeTab === 'state' && (
          <div className="space-y-6">
            <div className={`p-6 rounded-lg shadow border ${darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-gray-200'}`}>
              <div className="flex justify-between items-center mb-6">
                <div>
                  <h3 className={`text-xl font-bold flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-800'}`}>
                    <RefreshCw className="w-5 h-5 text-purple-600" /> Tabla de Conexiones Activas
                  </h3>
                  <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                    {isStateful
                      ? "Estas conexiones están 'establecidas'. El tráfico de retorno se permitirá automáticamente."
                      : "El modo Stateful está DESACTIVADO. Esta tabla estará vacía y no se recordarán conexiones."}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-2xl font-bold text-purple-600">{connections.length}</p>
                  <p className="text-xs text-gray-400 uppercase font-bold">Sesiones Activas</p>
                </div>
              </div>

              {!isStateful && (
                <div className={`p-4 rounded text-sm mb-4 flex items-center gap-2 border ${darkMode ? 'bg-yellow-900/20 border-yellow-900 text-yellow-200' : 'bg-yellow-50 border-yellow-200 text-yellow-800'}`}>
                  <AlertTriangle className="w-4 h-4" />
                  Activa el "Modo Stateful" en la barra superior para ver cómo se rellena esta tabla.
                </div>
              )}

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className={`uppercase ${darkMode ? 'bg-slate-800 text-gray-300' : 'bg-gray-100 text-gray-600'}`}>
                    <tr>
                      <th className="p-3">Inicio</th>
                      <th className="p-3">Origen</th>
                      <th className="p-3">Destino</th>
                      <th className="p-3">Protocolo</th>
                      <th className="p-3">Puertos</th>
                      <th className="p-3">TTL</th>
                    </tr>
                  </thead>
                  <tbody className={`divide-y font-mono text-xs ${darkMode ? 'divide-slate-800' : 'divide-gray-100'}`}>
                    {connections.map((conn) => (
                      <tr key={conn.id} className={`transition-colors ${darkMode ? 'hover:bg-slate-800 text-gray-300' : 'hover:bg-purple-50'}`}>
                        <td className={`p-3 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{conn.startTime}</td>
                        <td className={`p-3 font-bold ${darkMode ? 'text-gray-200' : 'text-gray-800'}`}>{conn.sourceIP}</td>
                        <td className={`p-3 ${darkMode ? 'text-gray-200' : 'text-gray-800'}`}>{conn.destIP}</td>
                        <td className={`p-3 font-bold ${darkMode ? 'text-purple-400' : 'text-purple-600'}`}>{conn.protocol}</td>
                        <td className={`p-3 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{conn.srcPort} : {conn.destPort}</td>
                        <td className="p-3">
                          <div className={`w-full rounded-full h-2.5 max-w-[100px] ${darkMode ? 'bg-slate-700' : 'bg-gray-200'}`}>
                            <div className="bg-green-500 h-2.5 rounded-full transition-all duration-1000" style={{ width: `${(conn.ttl / 15) * 100}%` }}></div>
                          </div>
                          <span className="text-[10px] text-gray-400">{conn.ttl}s</span>
                        </td>
                      </tr>
                    ))}
                    {connections.length === 0 && (
                      <tr>
                        <td colSpan="6" className="p-8 text-center text-gray-400 font-sans text-base">
                          {isStateful ? "Esperando tráfico aceptado..." : "Tabla inactiva (Stateless Mode)"}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Logs */}
        {activeTab === 'logs' && (
          <div className="space-y-4">

            <div className="flex justify-between items-center">
              <h3 className={`text-lg font-bold flex items-center gap-2 ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>
                Registro de Tráfico
                <span className={`text-xs px-2 py-1 rounded font-normal ${darkMode ? 'bg-blue-900/30 text-blue-300' : 'bg-blue-100 text-blue-700'}`}>Doble clic para inspeccionar</span>
              </h3>
              <button onClick={downloadCSV} className={`flex items-center gap-2 text-sm px-3 py-1.5 rounded transition-colors ${darkMode ? 'bg-slate-700 hover:bg-slate-600 text-gray-200' : 'bg-gray-200 hover:bg-gray-300 text-gray-700'}`}>
                <Download className="w-4 h-4" /> Exportar CSV
              </button>
            </div>

            <div className={`rounded-lg shadow border overflow-hidden ${darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-gray-200'}`}>
              <div className="overflow-y-auto max-h-[500px]">
                <table className="w-full text-left text-sm">
                  <thead className={`sticky top-0 shadow-sm ${darkMode ? 'bg-slate-800 text-gray-400' : 'bg-gray-50 text-gray-500'}`}>
                    <tr>
                      <th className="p-3">Hora</th>
                      <th className="p-3">Origen</th>
                      <th className="p-3">Proto</th>
                      <th className="p-3">Puerto</th>
                      <th className="p-3 w-1/4">Contenido / Info</th>
                      <th className="p-3">Acción</th>
                      <th className="p-3">Regla</th>
                    </tr>
                  </thead>
                  <tbody className={`divide-y font-mono text-xs ${darkMode ? 'divide-slate-800' : 'divide-gray-100'}`}>
                    {logs.map((log) => (
                      <tr
                        key={log.id}
                        onDoubleClick={() => setSelectedPacket(log)}
                        className={`cursor-pointer transition-colors ${log.isStatefulMatch ? (darkMode ? 'bg-purple-900/10' : 'bg-purple-50') : log.attackType ? (darkMode ? 'bg-red-900/10' : 'bg-red-50') : (darkMode ? 'hover:bg-slate-800' : 'hover:bg-gray-100')}`}
                        title="Doble clic para inspeccionar paquete"
                      >
                        <td className={`p-3 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{log.timestamp}</td>
                        <td className={`p-3 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                          {log.sourceIP}
                          {log.attackType && <div className="text-[9px] font-bold text-red-500 uppercase">{log.attackType}</div>}
                        </td>
                        <td className="p-3">
                          <span className={`px-1.5 py-0.5 rounded border ${log.protocol === 'TCP' ? (darkMode ? 'bg-blue-900/20 text-blue-300 border-blue-800' : 'bg-blue-50 text-blue-600 border-blue-200') :
                            log.protocol === 'UDP' ? (darkMode ? 'bg-orange-900/20 text-orange-300 border-orange-800' : 'bg-orange-50 text-orange-600 border-orange-200') :
                              (darkMode ? 'bg-slate-800 text-gray-400 border-slate-600' : 'bg-gray-100 text-gray-600 border-gray-300')
                            }`}>
                            {log.protocol}
                          </span>
                        </td>
                        <td className={`p-3 font-bold ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>{log.destPort}</td>
                        <td className={`p-3 truncate max-w-[200px] ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                          {log.isReturnTraffic && <span className={`text-[10px] px-1 rounded mr-1 ${darkMode ? 'bg-slate-700' : 'bg-gray-200'}`}>RESPUESTA</span>}
                          <span className={log.attackType ? (darkMode ? 'text-red-400 font-bold' : 'text-red-600 font-bold') : ''}>
                            {log.payload || (log.flags ? `Flags: ${log.flags}` : '-')}
                          </span>
                        </td>
                        <td className="p-3">
                          <span className={`font-bold ${log.action === 'ACCEPT' ? (darkMode ? 'text-green-400' : 'text-green-600') : (darkMode ? 'text-red-400' : 'text-red-600')}`}>
                            {log.action}
                          </span>
                        </td>
                        <td className={`p-3 truncate max-w-[150px] ${darkMode ? 'text-gray-400' : 'text-gray-500'}`} title={log.ruleName}>
                          {log.isStatefulMatch && <RefreshCw className={`w-3 h-3 inline mr-1 ${darkMode ? 'text-purple-400' : 'text-purple-600'}`} />}
                          {log.ruleName}
                        </td>
                      </tr>
                    ))}
                    {logs.length === 0 && <tr><td colSpan="7" className="p-8 text-center text-gray-400 font-sans text-base">Esperando tráfico...</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Simulador de Ataques / Inyección */}
        {activeTab === 'simulate' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-6">
            {/* Panel de Inyección Manual */}
            <div className={`p-8 rounded-lg shadow-lg border ${darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-gray-200'}`}>
              <h3 className={`text-xl font-bold mb-2 flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-800'}`}>
                <Activity className="w-5 h-5 text-blue-600" /> Inyección Manual
                <EduTooltip text="Crea un paquete a medida para probar tus reglas." />
              </h3>
              <p className={`text-sm mb-6 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Configura y envía un único paquete.</p>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className={`block text-xs font-bold mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>IP Origen</label>
                  <input type="text" value={manualPacket.sourceIP} onChange={e => setManualPacket({ ...manualPacket, sourceIP: e.target.value })} className={`w-full p-2 border rounded font-mono text-xs ${darkMode ? 'bg-slate-800 border-slate-600 text-white' : 'bg-gray-50'}`} />
                </div>
                <div>
                  <label className={`block text-xs font-bold mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>IP Destino</label>
                  <input type="text" value={manualPacket.destIP} onChange={e => setManualPacket({ ...manualPacket, destIP: e.target.value })} className={`w-full p-2 border rounded font-mono text-xs ${darkMode ? 'bg-slate-800 border-slate-600 text-white' : 'bg-gray-50'}`} />
                </div>
                <div>
                  <label className={`block text-xs font-bold mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Protocolo</label>
                  <select value={manualPacket.protocol} onChange={e => setManualPacket({ ...manualPacket, protocol: e.target.value })} className={`w-full p-2 border rounded text-xs ${darkMode ? 'bg-slate-800 border-slate-600 text-white' : 'bg-gray-50'}`}>
                    {PROTOCOLS.map(p => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <label className={`block text-xs font-bold mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Puerto Dest.</label>
                  <input type="number" value={manualPacket.destPort} onChange={e => setManualPacket({ ...manualPacket, destPort: e.target.value })} className={`w-full p-2 border rounded font-mono text-xs ${darkMode ? 'bg-slate-800 border-slate-600 text-white' : 'bg-gray-50'}`} />
                </div>
                <div className="col-span-2">
                  <label className={`block text-xs font-bold mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Payload (Contenido)</label>
                  <input type="text" placeholder="Ej: SELECT * FROM..." value={manualPacket.payload} onChange={e => setManualPacket({ ...manualPacket, payload: e.target.value })} className={`w-full p-2 border rounded font-mono text-xs ${darkMode ? 'bg-slate-800 border-slate-600 text-white' : 'bg-gray-50'}`} />
                </div>
              </div>
              <button onClick={handleManualInject} className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded shadow text-sm">Enviar Paquete Único</button>
            </div>

            {/* Panel de Ataques */}
            <div className={`p-8 rounded-lg shadow-inner border ${darkMode ? 'bg-slate-900 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
              <h3 className={`text-xl font-bold mb-2 flex items-center gap-2 ${darkMode ? 'text-red-400' : 'text-red-800'}`}>
                <Zap className="w-5 h-5 text-red-600" /> Generador de Ciberamenazas
                <EduTooltip text="Lanza ataques continuos para ver si tu firewall aguanta la carga." />
              </h3>
              <p className={`text-sm mb-6 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Selecciona un vector de ataque para simular tráfico hostil continuo.</p>

              <div className="space-y-4">
                <div className={`p-4 rounded border cursor-pointer transition-all ${attackMode === ATTACK_TYPES.SQL_INJECTION ? (darkMode ? 'bg-red-900/30 border-red-500' : 'bg-red-100 border-red-500 shadow-md') : (darkMode ? 'bg-slate-800 border-slate-600' : 'bg-white border-gray-200 hover:border-red-300')}`} onClick={() => toggleAttack(ATTACK_TYPES.SQL_INJECTION)}>
                  <div className="flex justify-between items-center mb-1">
                    <h4 className={`font-bold flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-800'}`}><Database className="w-4 h-4" /> SQL Injection Attack</h4>
                    {attackMode === ATTACK_TYPES.SQL_INJECTION && <span className="text-xs font-bold text-red-600 animate-pulse">ACTIVO</span>}
                  </div>
                  <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Intenta inyectar comandos SQL (ej: <code>' OR '1'='1'</code>) en el puerto 80. Requiere reglas DPI para bloquear.</p>
                </div>

                <div className={`p-4 rounded border cursor-pointer transition-all ${attackMode === ATTACK_TYPES.DDoS_UDP ? (darkMode ? 'bg-red-900/30 border-red-500' : 'bg-red-100 border-red-500 shadow-md') : (darkMode ? 'bg-slate-800 border-slate-600' : 'bg-white border-gray-200 hover:border-red-300')}`} onClick={() => toggleAttack(ATTACK_TYPES.DDoS_UDP)}>
                  <div className="flex justify-between items-center mb-1">
                    <h4 className={`font-bold flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-800'}`}><Globe className="w-4 h-4" /> DDoS UDP Flood</h4>
                    {attackMode === ATTACK_TYPES.DDoS_UDP && <span className="text-xs font-bold text-red-600 animate-pulse">ACTIVO</span>}
                  </div>
                  <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Inunda el puerto 53 (DNS) con tráfico UDP basura desde múltiples IPs. Genera mucho volumen.</p>
                </div>

                <div className={`p-4 rounded border cursor-pointer transition-all ${attackMode === ATTACK_TYPES.SYN_FLOOD ? (darkMode ? 'bg-red-900/30 border-red-500' : 'bg-red-100 border-red-500 shadow-md') : (darkMode ? 'bg-slate-800 border-slate-600' : 'bg-white border-gray-200 hover:border-red-300')}`} onClick={() => toggleAttack(ATTACK_TYPES.SYN_FLOOD)}>
                  <div className="flex justify-between items-center mb-1">
                    <h4 className={`font-bold flex items-center gap-2 ${darkMode ? 'text-white' : 'text-gray-800'}`}><Activity className="w-4 h-4" /> TCP SYN Flood</h4>
                    {attackMode === ATTACK_TYPES.SYN_FLOOD && <span className="text-xs font-bold text-red-600 animate-pulse">ACTIVO</span>}
                  </div>
                  <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Envía miles de solicitudes de conexión (SYN) sin completarlas para agotar la tabla de estados.</p>
                </div>
              </div>

              {attackMode !== ATTACK_TYPES.NONE && (
                <button onClick={() => { setAttackMode(ATTACK_TYPES.NONE); setIsRunning(false); }} className="w-full mt-6 bg-red-600 hover:bg-red-700 text-white font-bold py-2 rounded shadow text-sm">
                  DETENER ATAQUE
                </button>
              )}
            </div>
          </div>
        )}

      </main>
    </div>
  );
}