import { type Component } from "solid-js";

import styles from "./App.module.css";

const App: Component = () => {
  return (
    <div class={styles.App}>
      <header class={styles.header}>Welcome!</header>

      <form
        class={styles.form}
        onSubmit={async (e) => {
          e.preventDefault();

          await fetch("http://localhost:8080/login", {
            method: "POST",
            body: `{"username": "${e.target.username.value}", "password": "${e.target.password.value}"}`,
            credentials: "include",
          });

          await fetch("http://localhost:8080/whoami", {
            method: "GET",
            credentials: "include",
          });
        }}
      >
        <input
          id="username"
          name="username"
          placeholder="Username"
          class={styles.input}
        />

        <input
          id="password"
          name="password"
          placeholder="Password"
          type="password"
          class={styles.input}
        />

        <button class={styles.button}>Log In</button>
      </form>
    </div>
  );
};

export default App;
