import { Link } from 'react-router';
import { EmptyState, PageHeader } from '@/components/page';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';

export function NotFoundPage() {
  return (
    <>
      <PageHeader title="Not found" />
      <Card>
        <CardContent>
          <EmptyState title="This page doesn’t exist">
            <Button variant="outline" render={<Link to="/" />}>
              Back to overview
            </Button>
          </EmptyState>
        </CardContent>
      </Card>
    </>
  );
}
