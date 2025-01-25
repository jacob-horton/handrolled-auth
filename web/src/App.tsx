import type { Component } from "solid-js";

import styles from "./App.module.css";

const App: Component = () => {
  return (
    <div class={styles.App}>
      <header class={styles.header}>Welcome!</header>

      <form class={styles.form}>
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
      </form>

      <button class={styles.button}>Log In</button>
    </div>
  );
};

export default App;
