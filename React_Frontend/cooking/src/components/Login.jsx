import React,{useState} from "react";
import { Formik, Field, Form, ErrorMessage } from "formik";
import * as Yup from "yup";
import logo from '../style/images/logo.jpg'
import * as Icon from 'react-bootstrap-icons';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { useNavigate } from "react-router-dom";
import axios from "axios";
import BASE_URLS from "../constants/BASE_URLS";
function Login() {
  const navigateTo = useNavigate();
    const [visibleText, setVisibleText]=useState(false);
    const handleEye=()=>{
      setVisibleText((prevState => (
          !prevState
        )));
  }
  
  return (
    <div className="login-body">
      <div className="card-cover">
        <div className="login-card p-4 p-sm-3 ">
          <Formik
            initialValues={{ email: "", password: "" }}
            validationSchema={Yup.object({
              password: Yup.string()
                .required("Please Enter your password")
                .matches(
                  /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/,
                  "Must Contain 8 Characters, One Uppercase, One Lowercase, One Number and One Special Case Character"
                ),
              email: Yup.string()
                .email("Invalid email address")
                .required("Required"),
            })}
            onSubmit={(values) => {
              console.log("values",values)
              axios
                .post(`${BASE_URLS.baseUrl}/signin/`, {
                  "email": values.email,
                  "password": values.password,
                })
                .then(function (response) {
                console.log("response",response)
                console.log("token",response.data.acccess_token)
                if(response.data.acccess_token){
                  localStorage.setItem("token", response.data.acccess_token)
                  toast.success("Login Successfully");
                  setInterval(() => {
                    navigateTo('/landing')
                  }, 5000);
                }
                })
                .catch(function (error) {
                  toast.error("wrong username or password");
                });
                       
                 }}
          >
            <Form>
            <div className="logo">
                <img src={logo} alt="logo" />
              </div>
              <div className="head-title">
                <h2>Login</h2>
              </div>
              <div className="card-label-email">
                <label htmlFor="email">Email Address</label>
              </div>
              <div>
                <Field name="email" type="email" className="card-input-email" />
              </div>
              <div className="card-error">
                <ErrorMessage name="email" />
              </div>
              <div className="card-label-password">
                <label htmlFor="password">Password</label>
              </div>
              <div>
                {" "}
                <Field name="password" type={visibleText?"text":"password"} className="card-input-password"/>
                <span className="eye-lash" onClick={handleEye}><Icon.EyeSlash /></span>
              </div>
              <div className="card-error">
                <ErrorMessage name="password" />
              </div>
              <div className="card-button">
                <button type="submit">Submit</button>
              </div>
              <div className="signup-link">
                <p>Do you have an account? <span role="button" onClick={()=>{navigateTo('/signup')}}>Sign Up</span></p>
              </div>
              <ToastContainer />
            </Form>
          </Formik>
        </div>
      </div>
    </div>
  );
}
export default Login;