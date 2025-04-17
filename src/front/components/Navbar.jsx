import { Link, Routes } from "react-router-dom";
import useGlobalReducer from "../hooks/useGlobalReducer.jsx";

export const Navbar = () => {

	const { store, dispatch } = useGlobalReducer()

	return (
		<nav className="navbar navbar-light bg-light">
			<div className="container">

			<div>
				{/* {store.token !== null ? "You're logged in!!!! Here's the token." && store.token: "You're not logged in!!!" } */}
			<div>

				{store.token == null ? 
				
			    "You're not logged in!!!" :
				<div>

				<button onClick= {() => 
					dispatch({type: "updateToken", payload: null})
					}>
					Log Out
					</button>

					<h1>{store.token}</h1>
				</div>

					
				}
				


			</div>
			</div>

				<Link to="/">
					<span className="navbar-brand mb-0 h1">React Boilerplate</span>
				</Link>
				<div className="ml-auto">
					<Link to="/demo">
						<button className="btn btn-primary">Check the Context in action</button>
					</Link>
				</div>
			</div>
		</nav>
	);
};

// how to log in and go to a different page
// 1. go to Routes.jsx
// 2. add navigate PATH TO login in then response after dispatch
// 3. add a "private page" with the instructions above
// 4. go to Routes.jsx
// login, refresh as it stays logged in with sessions 