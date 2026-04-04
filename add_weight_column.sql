-- Add weight_kg column to checkins table for daily weight tracking
ALTER TABLE public.checkins
ADD COLUMN IF NOT EXISTS weight_kg DECIMAL(5,2) DEFAULT NULL;

-- Verify
SELECT column_name, data_type FROM information_schema.columns
WHERE table_name = 'checkins' AND table_schema = 'public'
ORDER BY ordinal_position;
