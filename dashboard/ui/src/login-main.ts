import './app.css';
import { mount } from 'svelte';
import Login from './Login.svelte';
import { initTheme } from './lib/theme';

initTheme();
mount(Login, { target: document.getElementById('app')! });
