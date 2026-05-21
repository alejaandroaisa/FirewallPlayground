import React, { createContext, useState, useEffect } from 'react';

// Creamos el contexto
export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(null);
    const [loading, setLoading] = useState(true);

    // Al cargar la app, miramos si ya hay un token guardado (por si recarga la página)
    useEffect(() => {
        const storedToken = localStorage.getItem('firewall_token');
        const storedUser = localStorage.getItem('firewall_user');

        if (storedToken && storedUser) {
            setToken(storedToken);
            setUser(JSON.parse(storedUser));
        }
        setLoading(false);
    }, []);

    // Función para hacer login (guarda en memoria y en localStorage)
    const login = (userData, jwtToken) => {
        setUser(userData);
        setToken(jwtToken);
        localStorage.setItem('firewall_token', jwtToken);
        localStorage.setItem('firewall_user', JSON.stringify(userData));
    };

    // Función para cerrar sesión
    const logout = () => {
        setUser(null);
        setToken(null);
        localStorage.removeItem('firewall_token');
        localStorage.removeItem('firewall_user');
    };

    if (loading) return <div>Cargando...</div>;

    return (
        <AuthContext.Provider value={{ user, token, login, logout, isAuthenticated: !!token }}>
            {children}
        </AuthContext.Provider>
    );
};