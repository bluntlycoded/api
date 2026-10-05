import { HttpError } from '../utils/httpError.js';

const notFound = (req, res) => res.status(404).json({ message: 'Not found' });

// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ message: err.message, ...err.extra });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ message: 'Invalid JSON body' });
  if (err.type === 'entity.too.large') return res.status(413).json({ message: 'Request body too large' });
  if (err.name === 'ValidationError' || err.name === 'CastError') {
    return res.status(400).json({ message: 'Invalid request data' });
  }
  if (err.code === 11000) return res.status(409).json({ message: 'Already exists' });

  console.error(`${req.method} ${req.originalUrl}:`, err.message);
  res.status(500).json({ message: 'Server error' });
};

export { notFound, errorHandler };
