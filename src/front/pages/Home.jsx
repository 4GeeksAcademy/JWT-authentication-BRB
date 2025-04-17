import React, { useEffect, useState } from "react"
import rigoImageUrl from "../assets/img/rigo-baby.jpg";
import useGlobalReducer from "../hooks/useGlobalReducer.jsx";
import { useNavigate } from "react-router-dom";

export const Home = () => {

	const { store, dispatch } = useGlobalReducer()
	const navigate = useNavigate()
	const [email, setEmail] = useState("")
	const [password, setPassword] = useState("")
	const [message, setMessage] = useState("")
	

	const loadMessage = async () => {
		try {
			const backendUrl = import.meta.env.VITE_BACKEND_URL

			if (!backendUrl) throw new Error("VITE_BACKEND_URL is not defined in .env file")

			const response = await fetch(backendUrl + "/api/hello")
			const data = await response.json()

			if (response.ok) dispatch({ type: "set_hello", payload: data.message })

			return data

		} catch (error) {
			if (error.message) throw new Error(
				`Could not fetch the message from the backend.
				Please check if the backend is running and the backend port is public.`
			);
		}

	}

	const handleLogin = ()=>{

		const option = {
			method: 'POST',
			body: JSON.stringify({
				"email": email,
				"password": password
			  }), 
			headers: {
			'Content-Type': 'application/json'
			}
	
		}
		fetch(import.meta.env.VITE_BACKEND_URL+"api/login", option) 
		.then((resp)=>{
			return resp.json()
		})
		.then((data) => {
			dispatch({type: "updateToken", payload: data.token_value }) 
			//  || when logged in, this should update token based off this dispatch & token recieved to update store variable.
				navigate("/demo")
		})

	}




	const handleCreate = ()=>{

		const option = {
			method: 'POST',
			body: JSON.stringify({
				"email": email,
				"password": password
			  }), 
			headers: {
			'Content-Type': 'application/json'
			}
	
		}
		fetch(import.meta.env.VITE_BACKEND_URL+"api/signup", option) 
		.then((resp)=>{
			return resp.json()
		})
		.then((data) => {
			console.log("DATA HERE!!!!!!",data)
			//  || when logged in, this should update token based off this dispatch & token recieved to update store variable.

		})

	}

	useEffect(() => {
		loadMessage()
		sessionStorage.setItem("TEST ITEM!!!!","TEST1")
	}, [])

	const testSession = sessionStorage.getItem["TEST ITEM!!!!"]

	return (
		<div>
			<input onChange={(e) => setEmail(e.target.value)} value={email} type="text" placeholder="Email" />
            <input onChange={(e) => setPassword(e.target.value)} value={password}  type="text" placeholder="Password" />

			<button onClick= {() => handleLogin()}>
					LogIn
			</button>


			<div className= "signup">
				<input onChange={(e) => setEmail(e.target.value)} value = {email} type="text" placeholder="Sign Up Email"/>
				<input onChange={(e) => setPassword(e.target.value)} value= {password} type="text" placeholder="password"/> 
				<button onClick={() =>handleCreate()}>
				Sign Up
				</button>


				<button onClick={() =>sessionStorage.setItem("TEST ITEM!!!!", "TEST2")} >
				 Here is the test: {testSession}
				</button>
			</div>

		{/* <span>
			{
				message
			}
		</span> */}
		</div>
	)
};