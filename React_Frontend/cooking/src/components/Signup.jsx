import React,{useState} from "react";
import { Formik, Field, Form, ErrorMessage } from "formik";
import * as Yup from "yup";
import logo from '../style/images/signuprecipe.jpg'
import * as Icon from 'react-bootstrap-icons';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { useNavigate } from "react-router-dom";
import axios from "axios";
import BASE_URLS from "../constants/BASE_URLS";
function Signup() {
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
        <div className="Signup-card p-4 p-sm-3 ">
          <Formik
            initialValues={{ email: "", password: "", confirmPassword:"" }}
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
                confirmPassword:  Yup.string()
                .oneOf([Yup.ref('password'), null], 'Passwords must match')
            })}
            onSubmit={(values) => {
              console.log("values",values)
              axios
                .post(`${BASE_URLS.baseUrl}/signup/`, {
                  "email": values.email,
                  "password": values.password,
                  "access_token": null
                })
                .then(function (response) {
                console.log("response",response)
                if(response.data.result === "Email Already exists"){
                  toast.error("Email Already exists");
                }else if(response.data.result === "Signup successfully"){
                  toast.success("Signup successfully");
                }else{
                  toast.error("try again");
                }
                })
                .catch(function (error) {
                  toast.error(error);
                });
            }}
          >
            <Form>
            <div className="logo">
                <img src={logo} alt="logo" />
              </div>
              <div className="head-title">
                <h2>Sign Up</h2>
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
              <div className="card-label-password">
                <label htmlFor="confirmPassword">Confirm Password</label>
              </div>
              <div>
                {" "}
                <Field name="confirmPassword" type="password" className="card-input-password"/>
              </div>
              <div className="card-error">
                <ErrorMessage name="confirmPassword" />
              </div>
              <div className="card-button">
                <button type="submit">Submit</button>
              </div>
              <div className="signup-link">
                <p>Back to &#x2192; <span role="button" onClick={()=>{navigateTo('/')}}>Login</span></p>
              </div>
              <ToastContainer />
            </Form>
          </Formik>
        </div>
      </div>
    </div>
  );
}
export default Signup;