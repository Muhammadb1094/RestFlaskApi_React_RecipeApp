import React, { useState, useEffect } from "react";
import logo from "../style/images/bg.jpg";
import { Tabs } from "antd";
import axios from "axios";
import BASE_URLS from "../constants/BASE_URLS";
import { Space, Table, Tag } from "antd";
import { Formik, Field, Form, ErrorMessage } from "formik";
import * as Yup from "yup";
import * as Icon from "react-bootstrap-icons";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

function LandingPage() {
const [dataTable, setDataTable] = useState()
const [edit, setEdit] = useState()
const [show, setShow] = useState(false)
const [count, setCount] = useState(0)
  useEffect(() => {
    axios
      .get(`${BASE_URLS.baseUrl}/get_all_recipes/`, {
        headers: { Authorization: `${BASE_URLS.token}` },
      })
      .then(function (response) {
        console.log("DataTable",response.data);
        setDataTable(response.data)
      })
      .catch(function (error) {
        console.log(error);
      });
  }, [count]);
  const handleEdit=(record)=>{
    setShow(true);
    setEdit(record)
  }
  const handleDelete =(id)=>{
    axios
    .get(`${BASE_URLS.baseUrl}/delete-recipe/${id}/`,)
    .then(function (response) {
      toast.success(response.data.result);
      console.log(response.data.result);
      setCount(prev => prev + 1)
    })
    .catch(function (error) {
      console.log(error);
      toast.error("Invalid Try")
    });
  }
  const columns = [
    {
      title: "ID",
      dataIndex: "id",
      key: "id",
    },
    {
      title: "Name",
      dataIndex: "name",
      key: "name",
    },
    {
      title: "Ingredients",
      dataIndex: "ingredients",
      key: "ingredients",
    },
    {
      title: "Instructions",
      dataIndex: "instructions",
      key: "instructions",
    },
    {
      title: "Serving Size",
      dataIndex: "serving_size",
      key: "serving_size",
    },
    {
      title: "Category",
      dataIndex: "category",
      key: "category",
    },
    {
      title: "Notes",
      dataIndex: "notes",
      key: "notes",
    },
    // {
    //   title: "Tags",
    //   key: "tags",
    //   dataIndex: "tags",
    //   render: (_, { tags }) => (
    //     <>
    //       {tags.map((tag) => {
    //         let color = tag.length > 5 ? "geekblue" : "green";
    //         if (tag === "loser") {
    //           color = "volcano";
    //         }
    //         return (
    //           <Tag color={color} key={tag}>
    //             {tag.toUpperCase()}
    //           </Tag>
    //         );
    //       })}
    //     </>
    //   ),
    // },
    {
      title: "Action",
      key: "action",
      render: (_, record) => (
        <Space size="middle">
          <p role="button" onClick={()=>handleEdit(record)}><Icon.Pencil /></p>
          <p role="button" onClick={()=>handleDelete(record.id)}><Icon.Trash /></p>
        </Space>
      ),
    },
  ];
  
  return (
    <div className="landing-body">
      <div className="landing-card-cover">
        <div className="landing-card">
          <div className="row main-top">
            <div className="col-xl-6 col-lg-6 col-md-12 col-sm-12 main-base">
              <div className="main-text">
                <div className="main-title">
                  <h2>Food Recipie</h2>
                </div>
                <div className="main-desp">
                  Cooking is an observation-based process that you can't do if
                  you're so completely focused on a recipe.
                  <span>-- Alton Brown</span>
                </div>
                <div class="main-card">
                  <div class="main-container">
                    <div className="row">
                      <div className="col-10 main-input">
                        <input type="text" />
                      </div>
                      <div className="col-2 main-button">
                        <button>search</button>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="row">
                  <div className="col-4 count-inner">
                    <p>100K</p>

                    <label htmlFor="">Recipes</label>
                  </div>
                  <div className="col-4 count-inner">
                    <p>400+</p>

                    <label htmlFor="">Cities</label>
                  </div>
                  <div className="col-4 count-inner">
                    <p>5000+</p>

                    <label htmlFor="">Contributors</label>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-6 col-lg-6 col-md-12 col-sm-12 main-portrait">
              <img src={logo} alt="logo" />
            </div>
          </div>
          <div className="main-tab">
            <Tabs defaultActiveKey="1" className="card-tab" centered>
              <Tabs.TabPane tab="Add Recipe" key="1">
                <div className="">
                  <Formik
                    initialValues={{
                      name: "",
                      ingredients: "",
                      instructions: "",
                      serving_size: "",
                      category: "",
                      notes: "",
                    }}
                    validationSchema={Yup.object({
                      ingredients: Yup.string().required("Required"),
                      name: Yup.string().required("Required"),
                      instructions: Yup.string().required("Required"),
                      serving_size: Yup.string().required("Required"),
                      category: Yup.string().required("Required"),
                      notes: Yup.string().required("Required"),
                    })}
                    onSubmit={(values) => {
                      console.log("values", values);
                      axios
                        .post(
                          `${BASE_URLS.baseUrl}/create-recipe/`,
                          {
                            name: values.name,
                            ingredients: values.ingredients,
                            instructions: values.instructions,
                            serving_size: values.serving_size,
                            category: values.category,
                            notes: values.notes,
                          },
                          {
                            headers: { Authorization: `${BASE_URLS.token}` },
                          },
                        )
                        .then(function (response) {
                          console.log("response", response);

                          toast.success("Created Successfully");
                        })
                        .catch(function (error) {
                          toast.error("Invalid Try");
                        });
                    }}
                  >
                    <Form>
                      <div className="head-title">
                        <h2>Create Recipie</h2>
                      </div>
                      <div className="row">
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="name">Name</label>
                          </div>
                          <div>
                            <Field
                              name="name"
                              type="text"
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="name" />
                          </div>
                        </div>
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="ingredients">Ingredients</label>
                          </div>
                          <div>
                            {" "}
                            <Field
                              name="ingredients"
                              type={"text"}
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="ingredients" />
                          </div>
                        </div>
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="instructions">Instructions</label>
                          </div>
                          <div>
                            {" "}
                            <Field
                              name="instructions"
                              type="text"
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="instructions" />
                          </div>
                        </div>
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="notes">notes</label>
                          </div>
                          <div>
                            {" "}
                            <Field
                              name="notes"
                              type="text"
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="notes" />
                          </div>
                        </div>
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="serving_size">Serving Size</label>
                          </div>
                          <div>
                            {" "}
                            <Field
                              name="serving_size"
                              type="number"
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="serving_size" />
                          </div>
                        </div>
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="category">Category</label>
                          </div>
                          <div>
                            {" "}
                            <Field
                              name="category"
                              type="text"
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="category" />
                          </div>
                        </div>
                      </div>
                      <div className="card-button-recipe">
                        <button type="submit">Create</button>
                      </div>
                      <ToastContainer />
                    </Form>
                  </Formik>
                </div>
              </Tabs.TabPane>
              <Tabs.TabPane tab="Recipe List"  key="2">
                {show?( <div className="">
                  <Formik
                    initialValues={{
                      name: edit.name,
                      ingredients: edit.ingredients,
                      instructions: edit.instructions,
                      serving_size: edit.serving_size,
                      category: edit.category,
                      notes: edit.notes,
                      id:edit.id
                    }}
                    validationSchema={Yup.object({
                      ingredients: Yup.string().required("Required"),
                      name: Yup.string().required("Required"),
                      instructions: Yup.string().required("Required"),
                      serving_size: Yup.string().required("Required"),
                      category: Yup.string().required("Required"),
                      notes: Yup.string().required("Required"),
                    })}
                    onSubmit={(values) => {
                      console.log("values", values);
                      axios
                        .post(
                          `${BASE_URLS.baseUrl}/create-recipe/`,
                          {
                            id: values.id,
                            name: values.name,
                            ingredients: values.ingredients,
                            instructions: values.instructions,
                            serving_size: values.serving_size,
                            category: values.category,
                            notes: values.notes,
                          },
                          {
                            headers: { Authorization: `${BASE_URLS.token}` },
                          },
                        )
                        .then(function (response) {
                          console.log("response", response);

                          toast.success("Updated Successfully");
                        })
                        .catch(function (error) {
                          toast.error("Invalid Try");
                        });
                    }}
                  >
                    <Form>
                      <div className="head-title">
                        <h2>Edit Recipie</h2>
                      </div>
                      <div className="row">
                      <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="name">ID</label>
                          </div>
                          <div>
                            <Field
                              name="id"
                              type="text"
                              disabled
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="id" />
                          </div>
                        </div>
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="name">Name</label>
                          </div>
                          <div>
                            <Field
                              name="name"
                              type="text"
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="name" />
                          </div>
                        </div>
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="ingredients">Ingredients</label>
                          </div>
                          <div>
                            {" "}
                            <Field
                              name="ingredients"
                              type={"text"}
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="ingredients" />
                          </div>
                        </div>
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="instructions">Instructions</label>
                          </div>
                          <div>
                            {" "}
                            <Field
                              name="instructions"
                              type="text"
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="instructions" />
                          </div>
                        </div>
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="notes">notes</label>
                          </div>
                          <div>
                            {" "}
                            <Field
                              name="notes"
                              type="text"
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="notes" />
                          </div>
                        </div>
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="serving_size">Serving Size</label>
                          </div>
                          <div>
                            {" "}
                            <Field
                              name="serving_size"
                              type="number"
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="serving_size" />
                          </div>
                        </div>
                        <div className="col-lg-6 col-md-12 col-sm-12">
                          <div className="card-label-password">
                            <label htmlFor="category">Category</label>
                          </div>
                          <div>
                            {" "}
                            <Field
                              name="category"
                              type="text"
                              className="card-input-recipe"
                            />
                          </div>
                          <div className="card-error">
                            <ErrorMessage name="category" />
                          </div>
                        </div>
                      </div>
                      <div className="card-button-recipe">
                        <button type="submit">Edit</button>
                      </div>
                      <ToastContainer />
                    </Form>
                  </Formik>
                </div>):""}
                <Table columns={columns} dataSource={dataTable} />
              </Tabs.TabPane>
            </Tabs>
          </div>
        </div>
      </div>
    </div>
  );
}

export default LandingPage;
