'use client';

import { createContext, useContext } from 'react';
import type { DeploymentSettings } from './api';

export const DeploymentContext = createContext<DeploymentSettings | null>(null);

export function useDeployment(): DeploymentSettings | null {
  return useContext(DeploymentContext);
}
