import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const APP_URL = 'http://localhost:8000';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    manifest: true,
  },
  // base: `${APP_URL}/react/dist/`,
})
