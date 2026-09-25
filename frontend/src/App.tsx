import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { HistoryPage } from './pages/HistoryPage';
import { NewScanPage } from './pages/NewScanPage';
import { LiveScanPage } from './pages/LiveScanPage';
import { TriageWorkspacePage } from './pages/TriageWorkspacePage';
import { NotFoundPage } from './pages/NotFoundPage';
import { ErrorBoundary } from './components/common/ErrorBoundary';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

export const App: React.FC = () => {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<HistoryPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/scans/history" element={<HistoryPage />} />
            <Route path="/scans/new" element={<NewScanPage />} />
            <Route path="/scans/:id/live" element={<LiveScanPage />} />
            <Route path="/scans/:id" element={<TriageWorkspacePage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  );
};

export default App;
