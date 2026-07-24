import {
  createRootRoute,
  createRoute,
  createRouter,
} from "@tanstack/react-router";

import { AppShell } from "./app-shell";
import { ClientsPage } from "./pages/clients";
import { IncidentsPage } from "./pages/incidents";
import { FirewallPage } from "./pages/firewall";
import { GlossaryPage } from "./pages/glossary";
import { OverviewPage } from "./pages/overview";
import { ProtectionPage } from "./pages/protection";
import { ResourcesPage } from "./pages/resources";
import { RoutesPage } from "./pages/routes";
import { TrafficPage } from "./pages/traffic";

const rootRoute = createRootRoute({ component: AppShell });

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: OverviewPage,
});

const trafficRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/traffic",
  component: TrafficPage,
});

const clientsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/clients",
  component: ClientsPage,
});

const routesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/routes",
  component: RoutesPage,
});

const incidentsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/incidents",
  component: IncidentsPage,
});

const resourcesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/resources",
  component: ResourcesPage,
});

const firewallRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/firewall",
  component: FirewallPage,
});

const protectionRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/protection",
  component: ProtectionPage,
});

const glossaryRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/glossary",
  component: GlossaryPage,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  trafficRoute,
  clientsRoute,
  routesRoute,
  incidentsRoute,
  resourcesRoute,
  protectionRoute,
  firewallRoute,
  glossaryRoute,
]);

export const router = createRouter({
  routeTree,
  defaultPreload: "intent",
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
