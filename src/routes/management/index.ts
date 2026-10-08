import { Router } from 'express';
import type { AppContext } from '../../context.ts';
import { actionRoutes } from './actions.ts';
import { managementAuthentication } from './auth.ts';
import { brandingThemeRoutes } from './branding-themes.ts';
import { clientRoutes } from './clients.ts';
import { connectionRoutes } from './connections.ts';
import { resourceServerRoutes } from './resource-servers.ts';
import { roleRoutes } from './roles.ts';
import { tenantSingletonRoutes } from './tenant-singletons.ts';
import { tenantRoutes } from './tenant.ts';
import { ticketRoutes } from './tickets.ts';
import { userRoutes } from './users.ts';

/** `/api/v2` router: authentication first, then every resource module. */
export function managementRouter(ctx: AppContext): Router {
    const router = Router();
    router.use(managementAuthentication(ctx));
    router.use(tenantRoutes(ctx));
    router.use(tenantSingletonRoutes(ctx));
    router.use(resourceServerRoutes(ctx));
    router.use(roleRoutes(ctx));
    router.use(clientRoutes(ctx));
    router.use(connectionRoutes(ctx));
    router.use(brandingThemeRoutes(ctx));
    router.use(actionRoutes(ctx));
    router.use(userRoutes(ctx));
    router.use(ticketRoutes(ctx));
    return router;
}
