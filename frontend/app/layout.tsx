import './globals.css';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';
export const metadata: Metadata = { title: 'ScamTrace | Community scam intelligence', description: 'Report, investigate and verify suspicious activity.' };
export default function RootLayout({children}:{children:ReactNode}) { return <html lang="en"><body>{children}</body></html>; }
