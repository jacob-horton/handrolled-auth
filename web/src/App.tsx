import { createResource, Show, type Component } from "solid-js";

import styles from "./App.module.css";

type Session = {
  loggedIn: boolean;
  username?: string;
};

const App: Component = () => {
  const [session, { refetch }] = createResource<Session>(async () => {
    const result = await fetch("http://localhost:8080/session", {
      method: "GET",
      credentials: "include",
    });

    if (!result.ok) {
      return { loggedIn: false };
    }

    return {
      loggedIn: true,
      username: await result.text(),
    };
  });

  return (
    <div class={styles.App}>
      <header class={styles.header}>Welcome!</header>

      <Show when={session()?.loggedIn}>
        <p>Logged in as {session()?.username}</p>
        <button
          class={styles.button}
          onClick={async () => {
            await fetch("http://localhost:8080/session", {
              method: "DELETE",
              credentials: "include",
            });

            refetch();
          }}
        >
          Log Out
        </button>
      </Show>
      <Show when={!session()?.loggedIn}>
        <form
          class={styles.form}
          onSubmit={async (e) => {
            e.preventDefault();

            const res = await fetch("http://localhost:8080/session", {
              method: "POST",
              body: `{"username": "${e.target.username.value}", "password": "${e.target.password.value}"}`,
              credentials: "include",
            });

            if (res.ok) {
              refetch();
            } else if (res.status == 401) {
              alert("Invalid password");
            } else {
              console.error(res.text());
            }
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
      </Show>
    </div>
  );
};

export default App;
