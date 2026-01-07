import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  Play,
  Pause,
  Plus,
  Trash2,
  ArrowUp,
  ArrowDown,
  Activity,
  FileText,
  Download,
  AlertTriangle,
  Settings,
  HelpCircle,
  RefreshCw,
  Zap,
  Database,
  Globe,
  CheckCircle,
  X,
  Layers,
  Binary,
  GraduationCap,
  ChevronRight,
  Move
} from 'lucide-react';

// --- Utilidades y Generadores de Datos (ORIGINALES v3) ---

const PROTOCOLS = ['TCP', 'UDP', 'ICMP'];
const ACTIONS = ['ACCEPT', 'DROP'];

// Generador de MACs aleatorias
const generateMAC = () => {
  return "XX:XX:XX:XX:XX:XX".replace(/X/g, function () {
    return "0123456789ABCDEF".charAt(Math.floor(Math.random() * 16));
  });
};

const SERVER_MAC = "00:50:56:C0:00:08";

// Genera una IP aleatoria o una IP "sospechosa"
const generateRandomIP = (isAttack = false) => {
  if (isAttack) return `192.168.1.${Math.floor(Math.random() * 50) + 200}`;
  return `192.168.1.${Math.floor(Math.random() * 100) + 1}`;
};

// Utilidad para generar datos deterministas
const getPseudoRandom = (seed, min, max) => {
  const x = Math.sin(seed) * 10000;
  const rand = x - Math.floor(x);
  return Math.floor(rand * (max - min + 1)) + min;
};

// Generador de Hex Dump simulado
const generateHexDump = (packet) => {
  const lines = [];
  let currentLine = "";
  let asciiLine = "";
  const totalBytes = 64 + (packet.payload ? packet.payload.length : 0);

  for (let i = 0; i < totalBytes; i++) {
    const byte = getPseudoRandom(packet.id + i, 0, 255);
    const hex = byte.toString(16).padStart(2, '0');
    currentLine += hex + " ";

    const char = (byte > 32 && byte < 126) ? String.fromCharCode(byte) : ".";
    asciiLine += char;

    if ((i + 1) % 16 === 0 || i === totalBytes - 1) {
      if (i === totalBytes - 1) {
        const remaining = 16 - ((i + 1) % 16);
        if (remaining < 16) {
          currentLine += "   ".repeat(remaining);
        }
      }
      const offset = (Math.floor(i / 16) * 10).toString().padStart(4, '0');
      lines.push(`${offset}   ${currentLine}   ${asciiLine}`);
      currentLine = "";
      asciiLine = "";
    }
  }
  return lines;
};

// --- Tipos de Ataques (ORIGINAL v3) ---
const ATTACK_TYPES = {
  NONE: 'NONE',
  SQL_INJECTION: 'SQL_INJECTION',
  DDoS_UDP: 'DDoS_UDP',
  SYN_FLOOD: 'SYN_FLOOD'
};

const generatePacket = (activeConnections = [], currentAttackMode = ATTACK_TYPES.NONE) => {
  const commonProps = {
    id: Date.now() + Math.random(),
    timestamp: new Date().toLocaleTimeString(),
    destIP: '10.0.0.5',
    destMAC: SERVER_MAC,
    ttl: 64,
    id_ip: Math.floor(Math.random() * 65535),
    seq_num: Math.floor(Math.random() * 4294967295),
    ack_num: Math.floor(Math.random() * 4294967295),
    window_size: 65535,
    checksum: Math.floor(Math.random() * 65535).toString(16).toUpperCase()
  };

  if (currentAttackMode === ATTACK_TYPES.SQL_INJECTION && Math.random() < 0.7) {
    return {
      ...commonProps,
      sourceIP: generateRandomIP(true),
      sourceMAC: generateMAC(),
      protocol: 'TCP',
      srcPort: Math.floor(Math.random() * 60000) + 1024,
      destPort: 80,
      isAttackSignature: true,
      flags: 'PSH, ACK',
      payload: "SELECT * FROM users WHERE id='1' OR '1'='1'",
      attackType: 'SQL Injection'
    };
  }

  if (currentAttackMode === ATTACK_TYPES.DDoS_UDP && Math.random() < 0.9) {
    return {
      ...commonProps,
      sourceIP: generateRandomIP(true),
      sourceMAC: generateMAC(),
      protocol: 'UDP',
      srcPort: Math.floor(Math.random() * 60000) + 1024,
      destPort: 53,
      isAttackSignature: true,
      flags: '',
      payload: '<Buffer Random Junk Data>',
      attackType: 'UDP Flood'
    };
  }

  if (currentAttackMode === ATTACK_TYPES.SYN_FLOOD && Math.random() < 0.8) {
    return {
      ...commonProps,
      sourceIP: generateRandomIP(true),
      sourceMAC: generateMAC(),
      protocol: 'TCP',
      srcPort: Math.floor(Math.random() * 60000) + 1024,
      destPort: 443,
      isAttackSignature: true,
      flags: 'SYN',
      payload: '',
      attackType: 'SYN Flood',
      window_size: 1024
    };
  }

  const isResponse = activeConnections.length > 0 && Math.random() < 0.3;
  if (isResponse) {
    const conn = activeConnections[Math.floor(Math.random() * activeConnections.length)];
    return {
      ...commonProps,
      id: Date.now() + Math.random(),
      timestamp: new Date().toLocaleTimeString(),
      sourceIP: conn.destIP,
      sourceMAC: SERVER_MAC,
      destIP: conn.sourceIP,
      destMAC: conn.sourceMAC || generateMAC(),
      protocol: conn.protocol,
      srcPort: conn.destPort,
      destPort: conn.srcPort,
      isAttackSignature: false,
      flags: 'ACK',
      isReturnTraffic: true,
      payload: 'HTTP/1.1 200 OK',
      ttl: 128
    };
  }

  const isAttack = Math.random() < 0.1;
  const protocol = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
  const commonPorts = [80, 443, 22, 21, 53, 8080];
  const port = isAttack ? 22 : commonPorts[Math.floor(Math.random() * commonPorts.length)];

  return {
    ...commonProps,
    sourceIP: generateRandomIP(isAttack),
    sourceMAC: generateMAC(),
    protocol: protocol,
    srcPort: Math.floor(Math.random() * 60000) + 1024,
    destPort: port,
    isAttackSignature: isAttack,
    flags: protocol === 'TCP' ? 'SYN' : '',
    isReturnTraffic: false,
    payload: isAttack ? 'SSH-2.0-OpenSSH_8.2p1' : (protocol === 'HTTP' ? 'GET /index.html HTTP/1.1' : ''),
    attackType: isAttack ? 'Port Scan' : ''
  };
};

// --- Componentes UI Auxiliares (ORIGINALES v3 RESTAURADOS) ---

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
      <span className={`invisible group-hover/tooltip:visible opacity-0 group-hover/tooltip:opacity-100 transition-opacity absolute ${tooltipPos} ${positionClasses[align]} px-3 py-2 bg-slate-800 text-white text-xs rounded shadow-lg w-64 text-center z-50 pointer-events-none whitespace-normal normal-case font-normal`}>
        {text}
        <span className={`absolute ${arrowPos} ${arrowClasses[align]} border-4 border-transparent`}></span>
      </span>
    </span>
  );
};

// --- PACKET INSPECTOR COMPLETO (RESTAURADO v3) ---
const PacketInspector = ({ packet, onClose }) => {
  if (!packet) return null;

  const hexDump = generateHexDump(packet);

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black bg-opacity-70 backdrop-blur-sm p-4 animate-fade-in font-sans">
      <div className="bg-white rounded-xl shadow-2xl max-w-4xl w-full overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="bg-slate-900 p-4 text-white flex justify-between items-center border-b border-slate-700">
          <div className="flex items-center gap-3">
            <div className="bg-blue-600 p-2 rounded-lg">
              <Layers className="w-5 h-5 text-white" />
            </div>
            <div>
              <h2 className="text-lg font-bold">Inspector de Paquete</h2>
              <p className="text-xs text-blue-200 font-mono">Frame {Math.floor(packet.id).toString().slice(-4)} | {packet.timestamp} | {packet.protocol}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white hover:bg-slate-800 p-2 rounded-full transition-colors">
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Content - Scrollable */}
        <div className="overflow-y-auto p-0 bg-gray-50 flex-1">

          {/* Layer 2: Ethernet */}
          <details open className="border-b border-gray-200 bg-white">
            <summary className="px-4 py-2 cursor-pointer hover:bg-gray-50 flex items-center justify-between select-none">
              <div className="font-bold text-sm text-gray-800 flex items-center gap-2">
                <span className="bg-gray-700 text-white text-[10px] px-1.5 rounded font-mono">L2</span>
                Ethernet II (Capa de Enlace)
              </div>
              <span className="text-xs text-gray-400">14 bytes</span>
            </summary>
            <div className="px-6 py-3 bg-gray-50 text-xs font-mono grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 border-t border-gray-100">
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">Destino <EduTooltip text="La dirección física (tarjeta de red) hacia donde va el paquete en la red local (LAN)." />:</span>
                <span>{packet.destMAC}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">Origen <EduTooltip text="La dirección física de quien envió el paquete en la red local." />:</span>
                <span>{packet.sourceMAC}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">Tipo <EduTooltip text="Indica qué protocolo de Capa 3 viene dentro (0x0800 es IPv4)." />:</span>
                <span>IPv4 (0x0800)</span>
              </div>
            </div>
            <div className="bg-yellow-50 px-4 py-2 text-xs text-yellow-800 border-t border-yellow-100 italic">
              <strong>Nota Educativa:</strong> Las direcciones MAC solo sirven para moverse "salto a salto" dentro de la misma red física (cables/wifi).
            </div>
          </details>

          {/* Layer 3: IP */}
          <details open className="border-b border-gray-200 bg-white">
            <summary className="px-4 py-2 cursor-pointer hover:bg-gray-50 flex items-center justify-between select-none">
              <div className="font-bold text-sm text-gray-800 flex items-center gap-2">
                <span className="bg-blue-600 text-white text-[10px] px-1.5 rounded font-mono">L3</span>
                Internet Protocol v4 (Capa de Red)
              </div>
              <span className="text-xs text-gray-400">20 bytes</span>
            </summary>
            <div className="px-6 py-3 bg-gray-50 text-xs font-mono grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 border-t border-gray-100">
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">Versión <EduTooltip text="Generalmente 4 (IPv4) o 6 (IPv6)." />:</span>
                <span>4</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">Longitud Total <EduTooltip text="Tamaño total del paquete IP incluyendo encabezado y datos." />:</span>
                <span>{40 + (packet.payload ? packet.payload.length : 0)}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">Identificación <EduTooltip text="Número único para rearmar el paquete si se fragmenta en trozos." />:</span>
                <span>0x{packet.id_ip ? packet.id_ip.toString(16) : '1A2B'}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">TTL (Time to Live) <EduTooltip text="Cuenta atrás de 'vidas'. Disminuye en cada router. Si llega a 0, el paquete muere (evita bucles infinitos)." />:</span>
                <span>{packet.ttl}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">Protocolo <EduTooltip text="Define qué hay en la capa superior (6=TCP, 17=UDP, 1=ICMP)." />:</span>
                <span>{packet.protocol} ({packet.protocol === 'TCP' ? 6 : packet.protocol === 'UDP' ? 17 : 1})</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">IP Origen <EduTooltip text="Dirección lógica de quien envía el mensaje en Internet." />:</span>
                <span className="font-bold">{packet.sourceIP}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">IP Destino <EduTooltip text="Dirección lógica final a donde debe llegar el mensaje." />:</span>
                <span className="font-bold">{packet.destIP}</span>
              </div>
            </div>
            <div className="bg-yellow-50 px-4 py-2 text-xs text-yellow-800 border-t border-yellow-100 italic">
              <strong>Nota Educativa:</strong> A diferencia de la MAC, la IP permite que el paquete viaje por todo el mundo a través de routers.
            </div>
          </details>

          {/* Layer 4: Transport */}
          <details open className="border-b border-gray-200 bg-white">
            <summary className="px-4 py-2 cursor-pointer hover:bg-gray-50 flex items-center justify-between select-none">
              <div className="font-bold text-sm text-gray-800 flex items-center gap-2">
                <span className="bg-purple-600 text-white text-[10px] px-1.5 rounded font-mono">L4</span>
                {packet.protocol === 'TCP' ? 'Transmission Control Protocol' : 'User Datagram Protocol'} (Capa de Transporte)
              </div>
              <span className="text-xs text-gray-400">{packet.protocol === 'TCP' ? '32 bytes' : '8 bytes'}</span>
            </summary>
            <div className="px-6 py-3 bg-gray-50 text-xs font-mono grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 border-t border-gray-100">
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">Puerto Origen <EduTooltip text="Puerta de salida de la aplicación en el ordenador emisor (aleatorio en clientes)." />:</span>
                <span>{packet.srcPort}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">Puerto Destino <EduTooltip text="Puerta de entrada en el servidor. Define el servicio (80=Web, 22=SSH)." />:</span>
                <span className="font-bold text-purple-700">{packet.destPort}</span>
              </div>

              {packet.protocol === 'TCP' && (
                <>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-500 flex items-center gap-1">Sequence Number <EduTooltip text="Número para ordenar los paquetes si llegan desordenados." />:</span>
                    <span>{packet.seq_num || 0}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-500 flex items-center gap-1">Ack Number <EduTooltip text="Confirma qué byte se espera recibir a continuación." />:</span>
                    <span>{packet.ack_num || 0}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-500 flex items-center gap-1">Flags <EduTooltip text="Banderas de control: SYN (conectar), ACK (confirmar), FIN (terminar), RST (error)." />:</span>
                    <span className="font-bold text-gray-700">{packet.flags}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-500 flex items-center gap-1">Window Size <EduTooltip text="Control de flujo: Cuántos datos puede recibir el destinatario antes de saturarse." />:</span>
                    <span>{packet.window_size || 65535}</span>
                  </div>
                </>
              )}
              {packet.protocol === 'UDP' && (
                <div className="flex justify-between items-center">
                  <span className="text-gray-500 flex items-center gap-1">Length <EduTooltip text="Longitud del datagrama UDP." />:</span>
                  <span>{8 + (packet.payload ? packet.payload.length : 0)}</span>
                </div>
              )}
              <div className="flex justify-between items-center">
                <span className="text-gray-500 flex items-center gap-1">Checksum <EduTooltip text="Suma de verificación para detectar errores en los datos." />:</span>
                <span>0x{packet.checksum || 'FAKE'}</span>
              </div>
            </div>
            <div className="bg-yellow-50 px-4 py-2 text-xs text-yellow-800 border-t border-yellow-100 italic">
              <strong>Nota Educativa:</strong> Esta capa se encarga de que los datos lleguen a la aplicación correcta (gracias a los puertos) y de forma fiable (si es TCP).
            </div>
          </details>

          {/* Layer 7: Application / Hex Dump */}
          <details open className="border-b border-gray-200 bg-white">
            <summary className="px-4 py-2 cursor-pointer hover:bg-gray-50 flex items-center justify-between select-none">
              <div className="font-bold text-sm text-gray-800 flex items-center gap-2">
                <span className="bg-orange-600 text-white text-[10px] px-1.5 rounded font-mono">Data</span>
                Capa de Aplicación / Datos (Payload)
              </div>
              <span className="text-xs text-gray-400">{packet.payload ? packet.payload.length : 0} bytes</span>
            </summary>

            <div className="p-4 bg-gray-50 border-t border-gray-100">
              {/* ASCII Representation */}
              {packet.payload && (
                <div className="mb-4">
                  <p className="text-xs text-gray-500 uppercase mb-1 font-bold flex items-center gap-1">
                    Payload (Texto Legible) <EduTooltip text="El mensaje real que envía el usuario (ej. comando SQL, página web)." />
                  </p>
                  <div className="bg-white border border-gray-200 p-2 rounded text-xs font-mono text-green-700 break-all shadow-inner">
                    {packet.payload}
                  </div>
                </div>
              )}

              {/* Hex Dump */}
              <div>
                <div className="flex justify-between items-end mb-1">
                  <p className="text-xs text-gray-500 uppercase font-bold flex items-center gap-1">
                    <Binary className="w-3 h-3" /> Vista Hexadecimal (Raw)
                    <EduTooltip text="Así ve el ordenador los datos: números hexadecimales. A la derecha ves su traducción a texto." />
                  </p>
                  {packet.attackType === 'SQL Injection' && <span className="text-[10px] text-red-600 font-bold bg-red-50 px-2 py-0.5 rounded border border-red-100">MALICIOUS PAYLOAD DETECTED</span>}
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
        <div className="bg-gray-100 p-3 border-t border-gray-200 text-right">
          <button onClick={onClose} className="bg-slate-800 hover:bg-slate-900 text-white font-bold py-2 px-6 rounded text-sm transition-colors shadow-sm">
            Cerrar
          </button>
        </div>
      </div>
    </div>
  );
};

// --- LOGICA DEL TUTORIAL (ACTUALIZADA: MODO AVANZADO) ---

const TUTORIAL_STEPS = [
  {
    id: 0,
    title: "Bootcamp de Ciberseguridad",
    content: "Aprenderás a proteger un servidor desde cero. El entrenamiento incluye: Reglas básicas, Stateful Inspection y defensa contra ataques de Inyección SQL usando DPI.",
    actionCheck: () => true,
    tab: 'dashboard'
  },
  {
    id: 1,
    title: "1. La Regla de Oro",
    content: "En seguridad, lo que no está permitido está prohibido. Ve a la pestaña 'Reglas' y cambia la Política por Defecto a DROP para cerrar todo acceso.",
    actionCheck: (state) => state.defaultPolicy === 'DROP' && state.activeTab === 'rules',
    tab: 'rules',
    hint: "Busca los botones arriba a la derecha en la pestaña Reglas."
  },
  {
    id: 2,
    title: "2. Abrir Servicio Web",
    content: "El servidor necesita servir páginas web. Añade una regla para aceptar tráfico TCP en el puerto 80 (HTTP).",
    actionCheck: (state) => state.rules.some(r => r.port == '80' && r.protocol === 'TCP' && r.action === 'ACCEPT'),
    tab: 'rules',
    hint: "Usa el formulario inferior. Puerto: 80, Protocolo: TCP, Acción: ACCEPT."
  },
  {
    id: 3,
    title: "3. Memoria de Conexión (Stateful)",
    content: "El firewall está bloqueando las respuestas del servidor porque no 'recuerda' las peticiones. Activa el 'Modo Stateful' en la barra superior para permitir respuestas automáticamente.",
    actionCheck: (state) => state.isStateful === true,
    tab: 'dashboard',
    hint: "Busca el interruptor 'Modo Stateful' en la barra superior azul oscura."
  },
  {
    id: 4,
    title: "4. Simular un Ciberataque",
    content: "Es hora de probar las defensas. Ve a la pestaña 'Simulador' y activa el ataque 'SQL Injection'.",
    actionCheck: (state) => state.activeTab === 'simulate' && state.attackMode === 'SQL_INJECTION',
    tab: 'simulate',
    hint: "Haz clic en el panel rojo 'SQL Injection Attack'."
  },
  {
    id: 5,
    title: "5. Análisis Forense (Inspección)",
    content: "El ataque está pasando porque el puerto 80 está abierto. Ve a 'Logs', busca una fila roja (SQL Injection) y haz DOBLE CLIC para inspeccionar el paquete.",
    // CORREGIDO: Usamos el string legible 'SQL Injection' que es lo que realmente contiene el paquete
    actionCheck: (state) => state.activeTab === 'logs' && state.selectedPacket && state.selectedPacket.attackType === 'SQL Injection',
    tab: 'logs',
    hint: "Doble clic en cualquier fila de la tabla de logs que tenga texto rojo."
  },
  {
    id: 6,
    title: "6. Defensa Profunda (DPI)",
    content: "Viste el comando 'SELECT' en el inspector? Eso es una inyección. Crea una regla nueva que tenga Contenido: 'SELECT' y Acción: DROP para bloquear este patrón.",
    actionCheck: (state) => state.rules.some(r => r.content.toUpperCase().includes('SELECT') && r.action === 'DROP'),
    tab: 'rules',
    hint: "Usa el campo 'Contenido (DPI)' en el formulario de reglas."
  },
  {
    id: 7,
    title: "¡Tutorial Completado!",
    content: "¡Excelente! Has configurado un firewall stateful con capacidad de inspección profunda de paquetes (DPI). Ahora estás listo para el modo libre.",
    actionCheck: () => true,
    tab: 'dashboard'
  }
];

// --- Componente Principal ---

export default function FirewallSimulator() {
  const [isRunning, setIsRunning] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [defaultPolicy, setDefaultPolicy] = useState('DROP');
  const [showIntro, setShowIntro] = useState(true);

  // Estados del Tutorial
  const [tutorialMode, setTutorialMode] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [showTutorialSuccess, setShowTutorialSuccess] = useState(false);
  const [stepComplete, setStepComplete] = useState(false); // NUEVO: Evita condiciones de carrera

  // Estados para arrastrar el widget
  const [tutorialPosition, setTutorialPosition] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const dragOffset = useRef({ x: 0, y: 0 });
  const tutorialWidgetRef = useRef(null);

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
    rules, defaultPolicy, isStateful, connections, attackMode
  });

  useEffect(() => {
    stateRef.current = { rules, defaultPolicy, isStateful, connections, attackMode };
  }, [rules, defaultPolicy, isStateful, connections, attackMode]);

  // --- Efecto de Arrastre (Drag) ---
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

  // --- Lógica del Tutorial (ROBUSTA) ---

  const startTutorial = () => {
    setTutorialMode(true);
    setCurrentStep(0);
    setStepComplete(false); // Resetear estado de completitud
    setShowIntro(false);
    // Resetear entorno para el tutorial
    setRules([]);
    setDefaultPolicy('ACCEPT');
    setStats({ total: 0, allowed: 0, blocked: 0, attackAttempts: 0, statefulMatches: 0 });
    setLogs([]);
    setIsRunning(false);
    setIsStateful(false);
    setActiveTab('dashboard');
  };

  const skipTutorial = () => {
    setTutorialMode(false);
    setShowIntro(false);
  };

  // EFECTO 1: Verificar si el paso actual se ha completado
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

  // EFECTO 2: Gestionar la transición al siguiente paso (temporizador)
  useEffect(() => {
    if (stepComplete) {
      // Mostrar éxito (excepto en el paso inicial 0)
      if (currentStep !== 0) {
        setShowTutorialSuccess(true);
        setTimeout(() => setShowTutorialSuccess(false), 2000);
      }

      const delay = currentStep === 0 ? 0 : 1500;
      const timer = setTimeout(() => {
        // Avanzar de paso de forma segura
        setCurrentStep(prev => {
          const next = prev + 1;
          // Doble chequeo de seguridad
          return next < TUTORIAL_STEPS.length ? next : prev;
        });
        setStepComplete(false); // Resetear para el siguiente paso
      }, delay);

      // Limpiar temporizador si el componente se desmonta o el tutorial se cancela
      return () => clearTimeout(timer);
    }
  }, [stepComplete]); // Solo depende de stepComplete, ignorando actualizaciones de stats

  // --- Motor del Firewall (ORIGINAL v3) ---

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
    const { rules, defaultPolicy, isStateful, connections } = stateRef.current;
    let actionTaken = defaultPolicy;
    let matchedRuleName = 'Política por Defecto';
    let isStatefulMatch = false;

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
      for (const rule of rules) {
        if (
          checkMatch(packet.sourceIP, rule.sourceIP) &&
          checkMatch(packet.destIP, rule.destIP) &&
          checkMatch(packet.protocol, rule.protocol) &&
          checkMatch(packet.destPort, rule.port) &&
          checkContentMatch(packet.payload, rule.content)
        ) {
          actionTaken = rule.action;
          matchedRuleName = rule.name;
          break;
        }
      }
    }

    if (isStateful && actionTaken === 'ACCEPT' && !isStatefulMatch && !packet.isReturnTraffic && packet.flags.includes('SYN')) {
      const newConn = {
        id: Date.now() + Math.random(),
        sourceIP: packet.sourceIP, destIP: packet.destIP,
        srcPort: packet.srcPort, destPort: packet.destPort,
        protocol: packet.protocol, ttl: 15, startTime: new Date().toLocaleTimeString(),
        // v3 original props just in case
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
      const speed = stateRef.current.attackMode !== ATTACK_TYPES.NONE ? 300 : 1500;
      intervalRef.current = setInterval(() => {
        const { connections, attackMode } = stateRef.current;
        processPacket(generatePacket(connections, attackMode));
      }, speed);
    } else {
      clearInterval(intervalRef.current);
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

  // --- Manejadores de UI ---
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
      // Manual props fix
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
    <div className="bg-white p-4 rounded-lg shadow border border-gray-200 flex items-center justify-between">
      <div>
        <div className="text-sm text-gray-500 font-medium flex items-center">
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
    const styles = type === 'ACCEPT' ? 'bg-green-100 text-green-800 border-green-200' : 'bg-red-100 text-red-800 border-red-200';
    return <span className={`px-2 py-1 rounded text-xs font-bold border ${styles}`}>{type}</span>;
  };

  // Safe access for tutorial steps in render
  const currentTutorialStepData = TUTORIAL_STEPS[currentStep] || TUTORIAL_STEPS[0];

  return (
    <div className="min-h-screen bg-gray-50 font-sans text-gray-800 relative pb-32">
      <PacketInspector packet={selectedPacket} onClose={() => setSelectedPacket(null)} />

      {/* --- Overlay Tutorial Widget (MODIFICADO: AHORA ES DRAGGABLE) --- */}
      {tutorialMode && (
        <div
          ref={tutorialWidgetRef}
          // FIX Z-INDEX: Changed from z-50 to z-[70] to appear above the modal (which is z-[60])
          className={`fixed z-[70] w-96 animate-fade-in-up ${tutorialPosition ? '' : 'bottom-6 right-6'}`}
          style={tutorialPosition ? { left: tutorialPosition.x, top: tutorialPosition.y } : {}}
        >
          {showTutorialSuccess && (
            <div className="absolute -top-16 left-0 right-0 bg-green-500 text-white p-2 rounded-lg shadow-lg text-center font-bold animate-bounce pointer-events-none">
              ¡Objetivo Completado!
            </div>
          )}

          <div className="bg-slate-900 rounded-xl shadow-2xl border-2 border-blue-500 overflow-hidden text-white">
            {/* Header: Ahora es el asa para arrastrar */}
            <div
              className="bg-gradient-to-r from-blue-600 to-blue-800 p-3 flex justify-between items-center cursor-move select-none"
              onMouseDown={handleMouseDown}
            >
              <div className="flex items-center gap-2 font-bold">
                <Move className="w-4 h-4 text-blue-200" />
                <GraduationCap className="w-5 h-5 text-white" />
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

      {/* Modal Introducción (MODIFICADO PARA INCLUIR TUTORIAL) */}
      {showIntro && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900 bg-opacity-90 backdrop-blur-sm p-4">
          <div className="bg-white rounded-xl shadow-2xl max-w-4xl w-full overflow-hidden animate-fade-in-up">
            <div className="bg-slate-900 p-6 text-white flex justify-between items-center">
              <div className="flex items-center gap-3">
                <Shield className="w-8 h-8 text-blue-400" />
                <h2 className="text-2xl font-bold">Bienvenido a Firewall Playground</h2>
              </div>
            </div>
            <div className="p-8">
              <p className="text-lg text-gray-600 mb-8 leading-relaxed">
                Elige un modo para comenzar:
              </p>
              <div className="grid md:grid-cols-2 gap-6">
                <button
                  onClick={startTutorial}
                  className="group relative bg-blue-50 p-6 rounded-xl border-2 border-blue-100 hover:border-blue-500 hover:shadow-lg transition-all text-left"
                >
                  <div className="bg-blue-600 w-12 h-12 rounded-full flex items-center justify-center mb-4 text-white group-hover:scale-110 transition-transform">
                    <GraduationCap className="w-6 h-6" />
                  </div>
                  <h3 className="text-xl font-bold text-gray-800 mb-2">Modo Entrenamiento</h3>
                  <p className="text-sm text-gray-600">
                    Recomendado para principiantes. Un tutorial guiado paso a paso donde aprenderás a configurar reglas básicas y proteger el servidor desde cero.
                  </p>
                </button>

                <button
                  onClick={skipTutorial}
                  className="group relative bg-white p-6 rounded-xl border-2 border-gray-100 hover:border-gray-400 hover:shadow-lg transition-all text-left"
                >
                  <div className="bg-gray-700 w-12 h-12 rounded-full flex items-center justify-center mb-4 text-white group-hover:scale-110 transition-transform">
                    <Activity className="w-6 h-6" />
                  </div>
                  <h3 className="text-xl font-bold text-gray-800 mb-2">Modo Libre</h3>
                  <p className="text-sm text-gray-600">
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
            <Shield className="w-8 h-8 text-blue-400" />
            <div>
              <h1 className="text-xl font-bold tracking-wide flex items-center gap-2">
                FireWall Playground {tutorialMode && <span className="bg-blue-600 text-[10px] px-2 py-0.5 rounded text-white uppercase tracking-wider">Modo Entrenamiento</span>}
                <span className="text-xs font-normal opacity-70 border border-slate-600 px-1 rounded bg-slate-800 ml-2">by Alejandro Aisa</span>
              </h1>
              <p className="text-xs text-gray-400">Simulador de Tráfico, DPI y Filtrado de Paquetes</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3 bg-slate-800 p-2 rounded-lg border border-slate-700">
              <span className="text-xs font-bold text-gray-300 flex items-center gap-1">
                Modo Stateful
                <EduTooltip side="bottom" text="Si está activo, el firewall recuerda las conexiones salientes y permite sus respuestas automáticamente sin reglas adicionales." />
              </span>
              <button
                onClick={() => setIsStateful(!isStateful)}
                disabled={tutorialMode && currentStep < 3} // Solo permitir cambiar stateful cuando toca
                className={`relative w-12 h-6 rounded-full transition-colors duration-200 ease-in-out focus:outline-none ${isStateful ? 'bg-blue-500' : 'bg-gray-600'} ${tutorialMode && currentStep < 3 ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <span className={`absolute left-1 top-1 w-4 h-4 bg-white rounded-full transition-transform duration-200 ease-in-out ${isStateful ? 'translate-x-6' : 'translate-x-0'}`} />
              </button>
            </div>

            <div className="h-8 w-px bg-slate-700 mx-2 hidden md:block"></div>

            <div className="flex items-center gap-2 bg-slate-800 px-3 py-1 rounded-full border border-slate-700">
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
              className={`flex items-center gap-2 px-4 py-2 rounded font-bold transition-colors ${isRunning ? 'bg-red-500 hover:bg-red-600' : 'bg-green-500 hover:bg-green-600'}`}
            >
              {isRunning ? <><Pause className="w-4 h-4" /> Detener</> : <><Play className="w-4 h-4" /> Iniciar</>}
            </button>
          </div>
        </div>

        {attackMode !== ATTACK_TYPES.NONE && (
          <div className="absolute top-full left-0 w-full bg-red-600 text-white text-center text-xs font-bold py-1 uppercase tracking-widest animate-pulse">
            ⚠️ Ciberataque en curso: {attackMode} ⚠️
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="container mx-auto p-4 mt-4">

        {/* Tabs */}
        <div className="flex gap-2 mb-6 border-b border-gray-200 overflow-x-auto pb-1">
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
                ? 'border-blue-600 text-blue-600 bg-blue-50'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:bg-gray-100'
                }`}
            >
              <tab.icon className="w-4 h-4" /> {tab.label}
              {/* Highlight Tutorial */}
              {tutorialMode && TUTORIAL_STEPS[currentStep].tab === tab.id && (
                <span className="w-2 h-2 rounded-full bg-blue-600 animate-ping absolute top-2 right-2" />
              )}
            </button>
          ))}
        </div>

        {/* VISTA: Dashboard */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
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
              <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
                <h3 className="text-lg font-bold mb-4 text-gray-700">Top IPs de Origen (Recientes)</h3>
                <div className="space-y-2">
                  {Object.entries(logs.reduce((acc, log) => {
                    acc[log.sourceIP] = (acc[log.sourceIP] || 0) + 1;
                    return acc;
                  }, {}))
                    .sort(([, a], [, b]) => b - a)
                    .slice(0, 5)
                    .map(([ip, count], idx) => (
                      <div key={ip} className="flex justify-between items-center p-2 bg-gray-50 rounded">
                        <div className="flex items-center gap-2">
                          <span className="w-6 h-6 bg-blue-100 text-blue-600 rounded-full flex items-center justify-center text-xs font-bold">{idx + 1}</span>
                          <span className="font-mono text-sm">{ip}</span>
                        </div>
                        <span className="text-xs font-bold bg-gray-200 px-2 py-1 rounded text-gray-600">{count} pkt</span>
                      </div>
                    ))}
                  {logs.length === 0 && <p className="text-gray-400 italic text-center">Sin datos. Inicia la simulación.</p>}
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
                <h3 className="text-lg font-bold mb-4 text-gray-700 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-orange-600" />
                  Tipos de Tráfico Detectado
                </h3>
                <div className="space-y-3">
                  {['SQL Injection', 'UDP Flood', 'SYN Flood', 'Port Scan'].map(type => {
                    const count = logs.filter(l => l.attackType === type).length;
                    const width = logs.length > 0 ? (count / logs.length) * 100 : 0;
                    return (
                      <div key={type}>
                        <div className="flex justify-between text-xs mb-1">
                          <span className="font-bold text-gray-600">{type}</span>
                          <span className="text-gray-400">{count} eventos</span>
                        </div>
                        <div className="w-full bg-gray-100 rounded-full h-2">
                          <div className="bg-orange-500 h-2 rounded-full transition-all duration-500" style={{ width: `${width}%` }}></div>
                        </div>
                      </div>
                    )
                  })}
                  {logs.filter(l => l.attackType).length === 0 && <p className="text-xs text-gray-400 text-center py-4">No se han detectado firmas de ataque aún.</p>}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* VISTA: Reglas */}
        {activeTab === 'rules' && (
          <div className="space-y-6">
            <div className={`bg-white p-6 rounded-lg shadow border transition-all duration-300 ${tutorialMode && currentStep === 1 ? 'border-blue-500 ring-2 ring-blue-200' : 'border-gray-200'}`}>
              <div className="flex justify-between items-center mb-4 pb-4 border-b">
                <div>
                  <h3 className="text-lg font-bold text-gray-800 flex items-center">
                    Política por Defecto
                    <EduTooltip text="Es la red de seguridad. Si un paquete NO coincide con ninguna regla de la lista inferior, se le aplicará esta acción." />
                  </h3>
                  <p className="text-sm text-gray-500">Qué hacer si un paquete no coincide con ninguna regla.</p>
                </div>
                <div className="flex items-center bg-gray-100 p-1 rounded-lg">
                  {ACTIONS.map(action => (
                    <button
                      key={action}
                      onClick={() => setDefaultPolicy(action)}
                      className={`px-4 py-2 rounded-md text-sm font-bold transition-colors ${defaultPolicy === action
                        ? (action === 'ACCEPT' ? 'bg-green-500 text-white' : 'bg-red-500 text-white')
                        : 'text-gray-500 hover:bg-gray-200'
                        }`}
                    >
                      {action}
                    </button>
                  ))}
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-gray-100 text-gray-600 uppercase">
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
                  <tbody className="divide-y divide-gray-100">
                    {rules.map((rule, index) => (
                      <tr key={rule.id} className="hover:bg-gray-50">
                        <td className="p-3 font-bold text-gray-400">{index + 1}</td>
                        <td className="p-3 font-medium">{rule.name}</td>
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

            <div className={`bg-blue-50 p-6 rounded-lg border transition-all duration-300 ${tutorialMode && (currentStep === 2 || currentStep === 6) ? 'border-blue-500 ring-4 ring-blue-100' : 'border-blue-100'}`}>
              <h3 className="text-md font-bold text-blue-800 mb-4 flex items-center gap-2">
                <Plus className="w-4 h-4" /> Añadir Nueva Regla
                <EduTooltip text="Define los criterios específicos. Un asterisco (*) significa 'cualquiera'. Usa 'Contenido' para filtrar payloads específicos." />
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-8 gap-2 items-end">
                <div className="md:col-span-2">
                  <label className="block text-xs font-bold text-blue-800 mb-1">Nombre</label>
                  <input type="text" placeholder="Ej: Bloquear SQL" className="w-full p-2 border rounded text-sm" value={newRule.name} onChange={e => setNewRule({ ...newRule, name: e.target.value })} />
                </div>
                <div>
                  <label className="block text-xs font-bold text-blue-800 mb-1">IP Origen</label>
                  <input type="text" placeholder="*" className="w-full p-2 border rounded text-sm font-mono" value={newRule.sourceIP} onChange={e => setNewRule({ ...newRule, sourceIP: e.target.value })} />
                </div>
                <div>
                  <label className="block text-xs font-bold text-blue-800 mb-1">Proto</label>
                  <select className="w-full p-2 border rounded text-sm" value={newRule.protocol} onChange={e => setNewRule({ ...newRule, protocol: e.target.value })}>
                    <option value="*">Todos</option>
                    {PROTOCOLS.map(p => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-bold text-blue-800 mb-1">Puerto</label>
                  <input type="text" placeholder="*" className="w-full p-2 border rounded text-sm font-mono" value={newRule.port} onChange={e => setNewRule({ ...newRule, port: e.target.value })} />
                </div>
                <div className="md:col-span-2">
                  <label className="block text-xs font-bold text-blue-800 mb-1 flex items-center gap-1">
                    Contenido (DPI)
                    <EduTooltip text="Inspección Profunda de Paquetes. Escribe una palabra clave (ej: 'SELECT') para bloquear paquetes que la contengan." />
                  </label>
                  <input type="text" placeholder="Ej: DROP TABLE" className="w-full p-2 border rounded text-sm font-mono border-orange-200 bg-orange-50" value={newRule.content} onChange={e => setNewRule({ ...newRule, content: e.target.value })} />
                </div>
                <div>
                  <label className="block text-xs font-bold text-blue-800 mb-1">Acción</label>
                  <select className="w-full p-2 border rounded text-sm font-bold" value={newRule.action} onChange={e => setNewRule({ ...newRule, action: e.target.value })}>
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
            <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
              <div className="flex justify-between items-center mb-6">
                <div>
                  <h3 className="text-xl font-bold text-gray-800 flex items-center gap-2">
                    <RefreshCw className="w-5 h-5 text-purple-600" /> Tabla de Conexiones Activas
                  </h3>
                  <p className="text-sm text-gray-500">
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
                <div className="bg-yellow-50 border border-yellow-200 p-4 rounded text-yellow-800 text-sm mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Activa el "Modo Stateful" en la barra superior para ver cómo se rellena esta tabla.
                </div>
              )}

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-gray-100 text-gray-600 uppercase">
                    <tr>
                      <th className="p-3">Inicio</th>
                      <th className="p-3">Origen</th>
                      <th className="p-3">Destino</th>
                      <th className="p-3">Protocolo</th>
                      <th className="p-3">Puertos</th>
                      <th className="p-3">TTL</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 font-mono text-xs">
                    {connections.map((conn) => (
                      <tr key={conn.id} className="hover:bg-purple-50 transition-colors">
                        <td className="p-3 text-gray-500">{conn.startTime}</td>
                        <td className="p-3 text-gray-800 font-bold">{conn.sourceIP}</td>
                        <td className="p-3 text-gray-800">{conn.destIP}</td>
                        <td className="p-3 text-purple-600 font-bold">{conn.protocol}</td>
                        <td className="p-3 text-gray-500">{conn.srcPort} : {conn.destPort}</td>
                        <td className="p-3">
                          <div className="w-full bg-gray-200 rounded-full h-2.5 max-w-[100px]">
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

        {/* VISTA: Logs */}
        {activeTab === 'logs' && (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-lg font-bold text-gray-700 flex items-center gap-2">
                Registro de Tráfico
                <span className="text-xs bg-blue-100 text-blue-700 px-2 py-1 rounded font-normal">Doble clic para inspeccionar</span>
              </h3>
              <button onClick={downloadCSV} className="flex items-center gap-2 text-sm bg-gray-200 hover:bg-gray-300 px-3 py-1.5 rounded text-gray-700 transition-colors">
                <Download className="w-4 h-4" /> Exportar CSV
              </button>
            </div>

            <div className="bg-white rounded-lg shadow border border-gray-200 overflow-hidden">
              <div className="overflow-y-auto max-h-[500px]">
                <table className="w-full text-left text-sm">
                  <thead className="bg-gray-50 text-gray-500 sticky top-0 shadow-sm">
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
                  <tbody className="divide-y divide-gray-100 font-mono text-xs">
                    {logs.map((log) => (
                      <tr
                        key={log.id}
                        onDoubleClick={() => setSelectedPacket(log)}
                        className={`cursor-pointer hover:bg-gray-100 transition-colors ${log.isStatefulMatch ? 'bg-purple-50' : log.attackType ? 'bg-red-50' : ''}`}
                        title="Doble clic para inspeccionar paquete"
                      >
                        <td className="p-3 text-gray-500">{log.timestamp}</td>
                        <td className="p-3 text-gray-700">
                          {log.sourceIP}
                          {log.attackType && <div className="text-[9px] font-bold text-red-500 uppercase">{log.attackType}</div>}
                        </td>
                        <td className="p-3">
                          <span className={`px-1.5 py-0.5 rounded border ${log.protocol === 'TCP' ? 'bg-blue-50 text-blue-600 border-blue-200' :
                            log.protocol === 'UDP' ? 'bg-orange-50 text-orange-600 border-orange-200' :
                              'bg-gray-100 text-gray-600 border-gray-300'
                            }`}>
                            {log.protocol}
                          </span>
                        </td>
                        <td className="p-3 font-bold text-gray-600">{log.destPort}</td>
                        <td className="p-3 truncate max-w-[200px]">
                          {log.isReturnTraffic && <span className="text-[10px] bg-gray-200 px-1 rounded mr-1">RESPUESTA</span>}
                          <span className={log.attackType ? 'text-red-600 font-bold' : 'text-gray-500'}>
                            {log.payload || (log.flags ? `Flags: ${log.flags}` : '-')}
                          </span>
                        </td>
                        <td className="p-3">
                          <span className={`font-bold ${log.action === 'ACCEPT' ? 'text-green-600' : 'text-red-600'}`}>
                            {log.action}
                          </span>
                        </td>
                        <td className="p-3 text-gray-500 truncate max-w-[150px]" title={log.ruleName}>
                          {log.isStatefulMatch && <RefreshCw className="w-3 h-3 inline mr-1 text-purple-600" />}
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

        {/* VISTA: Simulador de Ataques / Inyección */}
        {activeTab === 'simulate' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-6">
            {/* Panel de Inyección Manual */}
            <div className="bg-white p-8 rounded-lg shadow-lg border border-gray-200">
              <h3 className="text-xl font-bold text-gray-800 mb-2 flex items-center gap-2">
                <Activity className="w-5 h-5 text-blue-600" /> Inyección Manual
                <EduTooltip text="Crea un paquete a medida para probar tus reglas." />
              </h3>
              <p className="text-sm text-gray-500 mb-6">Configura y envía un único paquete.</p>

              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <label className="block text-xs font-bold text-gray-700 mb-1">IP Origen</label>
                  <input type="text" value={manualPacket.sourceIP} onChange={e => setManualPacket({ ...manualPacket, sourceIP: e.target.value })} className="w-full p-2 border rounded bg-gray-50 font-mono text-xs" />
                </div>
                <div>
                  <label className="block text-xs font-bold text-gray-700 mb-1">IP Destino</label>
                  <input type="text" value={manualPacket.destIP} onChange={e => setManualPacket({ ...manualPacket, destIP: e.target.value })} className="w-full p-2 border rounded bg-gray-50 font-mono text-xs" />
                </div>
                <div>
                  <label className="block text-xs font-bold text-gray-700 mb-1">Protocolo</label>
                  <select value={manualPacket.protocol} onChange={e => setManualPacket({ ...manualPacket, protocol: e.target.value })} className="w-full p-2 border rounded bg-gray-50 text-xs">
                    {PROTOCOLS.map(p => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-bold text-gray-700 mb-1">Puerto Dest.</label>
                  <input type="number" value={manualPacket.destPort} onChange={e => setManualPacket({ ...manualPacket, destPort: e.target.value })} className="w-full p-2 border rounded bg-gray-50 font-mono text-xs" />
                </div>
                <div className="col-span-2">
                  <label className="block text-xs font-bold text-gray-700 mb-1">Payload (Contenido)</label>
                  <input type="text" placeholder="Ej: SELECT * FROM..." value={manualPacket.payload} onChange={e => setManualPacket({ ...manualPacket, payload: e.target.value })} className="w-full p-2 border rounded bg-gray-50 font-mono text-xs" />
                </div>
              </div>
              <button onClick={handleManualInject} className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded shadow text-sm">Enviar Paquete Único</button>
            </div>

            {/* Panel de Amenazas */}
            <div className="bg-slate-50 p-8 rounded-lg shadow-inner border border-slate-200">
              <h3 className="text-xl font-bold text-red-800 mb-2 flex items-center gap-2">
                <Zap className="w-5 h-5 text-red-600" /> Generador de Ciberamenazas
                <EduTooltip text="Lanza ataques continuos para ver si tu firewall aguanta la carga." />
              </h3>
              <p className="text-sm text-gray-600 mb-6">Selecciona un vector de ataque para simular tráfico hostil continuo.</p>

              <div className="space-y-4">
                <div className={`p-4 rounded border cursor-pointer transition-all ${attackMode === ATTACK_TYPES.SQL_INJECTION ? 'bg-red-100 border-red-500 shadow-md' : 'bg-white border-gray-200 hover:border-red-300'}`} onClick={() => toggleAttack(ATTACK_TYPES.SQL_INJECTION)}>
                  <div className="flex justify-between items-center mb-1">
                    <h4 className="font-bold text-gray-800 flex items-center gap-2"><Database className="w-4 h-4" /> SQL Injection Attack</h4>
                    {attackMode === ATTACK_TYPES.SQL_INJECTION && <span className="text-xs font-bold text-red-600 animate-pulse">ACTIVO</span>}
                  </div>
                  <p className="text-xs text-gray-500">Intenta inyectar comandos SQL (ej: <code>' OR '1'='1'</code>) en el puerto 80. Requiere reglas DPI para bloquear.</p>
                </div>

                <div className={`p-4 rounded border cursor-pointer transition-all ${attackMode === ATTACK_TYPES.DDoS_UDP ? 'bg-red-100 border-red-500 shadow-md' : 'bg-white border-gray-200 hover:border-red-300'}`} onClick={() => toggleAttack(ATTACK_TYPES.DDoS_UDP)}>
                  <div className="flex justify-between items-center mb-1">
                    <h4 className="font-bold text-gray-800 flex items-center gap-2"><Globe className="w-4 h-4" /> DDoS UDP Flood</h4>
                    {attackMode === ATTACK_TYPES.DDoS_UDP && <span className="text-xs font-bold text-red-600 animate-pulse">ACTIVO</span>}
                  </div>
                  <p className="text-xs text-gray-500">Inunda el puerto 53 (DNS) con tráfico UDP basura desde múltiples IPs. Genera mucho volumen.</p>
                </div>

                <div className={`p-4 rounded border cursor-pointer transition-all ${attackMode === ATTACK_TYPES.SYN_FLOOD ? 'bg-red-100 border-red-500 shadow-md' : 'bg-white border-gray-200 hover:border-red-300'}`} onClick={() => toggleAttack(ATTACK_TYPES.SYN_FLOOD)}>
                  <div className="flex justify-between items-center mb-1">
                    <h4 className="font-bold text-gray-800 flex items-center gap-2"><Activity className="w-4 h-4" /> TCP SYN Flood</h4>
                    {attackMode === ATTACK_TYPES.SYN_FLOOD && <span className="text-xs font-bold text-red-600 animate-pulse">ACTIVO</span>}
                  </div>
                  <p className="text-xs text-gray-500">Envía miles de solicitudes de conexión (SYN) sin completarlas para agotar la tabla de estados.</p>
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