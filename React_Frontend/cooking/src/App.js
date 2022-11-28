import './App.css';
import Login from './pages/login';
import Landing from './pages/landing';
import Signup from './pages/signup';
import './style/global.css'
import 'bootstrap/dist/css/bootstrap.min.css';
import APP_URLS  from './constants/APP_URLS';
import { Routes, Route } from 'react-router-dom';
function App() {
  return (
    <div className="App">
      <Routes>
  <Route path={APP_URLS.LOGIN} element={<Login/>} />
  <Route path={APP_URLS.SIGNUP} element={<Signup/>} />
  <Route path={APP_URLS.LANDING} element={<Landing/>} />
</Routes>
      
    </div>
  );
}

export default App;
