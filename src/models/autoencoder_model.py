"""
PyTorch Deep Autoencoder for Unsupervised Network Anomaly Detection in CyberSentinel.
Trained strictly on benign traffic; detects intrusions via reconstruction error deviation.
Implements validation-driven threshold optimization, early stopping, and CPU efficiency.
"""
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
import json
import logging
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import f1_score, precision_recall_curve

logger = logging.getLogger(__name__)


class FlowAutoencoderNet(nn.Module):
    """
    Symmetric deep compression and reconstruction network for network flow vectors.
    """

    def __init__(self, input_dim: int, latent_dim: int = 12):
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim

        # Encoder: compress high-dimensional flow statistics into latent manifold
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 48),
            nn.BatchNorm1d(48),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.1),
            nn.Linear(48, 24),
            nn.BatchNorm1d(24),
            nn.LeakyReLU(0.2),
            nn.Linear(24, latent_dim),
        )

        # Decoder: reconstruct normal flow dynamics from latent manifold
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 24),
            nn.BatchNorm1d(24),
            nn.LeakyReLU(0.2),
            nn.Linear(24, 48),
            nn.BatchNorm1d(48),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.1),
            nn.Linear(48, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed


class CyberSentinelAutoencoder:
    """
    Complete Autoencoder Pipeline Wrapper: training, threshold determination,
    and anomaly detection evaluation.
    """

    def __init__(
        self,
        latent_dim: int = 12,
        learning_rate: float = 1e-3,
        weight_decay: float = 1e-5,
        device: str = "cpu",
        random_seed: int = 42,
    ):
        self.latent_dim = latent_dim
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.device = torch.device(device)
        self.random_seed = random_seed

        torch.manual_seed(random_seed)
        np.random.seed(random_seed)

        self.net_: Optional[FlowAutoencoderNet] = None
        self.input_dim_: int = 0
        self.threshold_: float = 0.0
        self.threshold_strategy_: str = "val_f1_optimal"
        self.benign_val_mean_error_: float = 0.0
        self.benign_val_std_error_: float = 0.0
        self.training_losses_: List[float] = []
        self.validation_losses_: List[float] = []
        self.is_fitted_: bool = False

    def fit(
        self,
        X_train_benign: np.ndarray,
        X_val_benign: np.ndarray,
        batch_size: int = 128,
        max_epochs: int = 40,
        patience: int = 8,
    ):
        """
        Train the autoencoder ONLY on benign network flows.
        """
        self.input_dim_ = X_train_benign.shape[1]
        self.net_ = FlowAutoencoderNet(input_dim=self.input_dim_, latent_dim=self.latent_dim).to(self.device)

        train_tensor = torch.tensor(X_train_benign, dtype=torch.float32)
        val_tensor = torch.tensor(X_val_benign, dtype=torch.float32)

        train_loader = DataLoader(
            TensorDataset(train_tensor, train_tensor),
            batch_size=batch_size,
            shuffle=True,
            drop_last=False,
        )

        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(
            self.net_.parameters(),
            lr=self.learning_rate,
            weight_decay=self.weight_decay,
        )
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode="min", factor=0.5, patience=3
        )

        best_val_loss = float("inf")
        best_state = None
        patience_counter = 0

        logger.info(f"Training Autoencoder on {len(X_train_benign)} benign flows (epochs={max_epochs})...")

        for epoch in range(1, max_epochs + 1):
            # Training phase
            self.net_.train()
            running_train_loss = 0.0
            for batch_x, _ in train_loader:
                batch_x = batch_x.to(self.device)
                optimizer.zero_grad()
                recon = self.net_(batch_x)
                loss = criterion(recon, batch_x)
                loss.backward()
                optimizer.step()
                running_train_loss += loss.item() * len(batch_x)

            epoch_train_loss = running_train_loss / len(X_train_benign)
            self.training_losses_.append(epoch_train_loss)

            # Validation phase (on benign validation flows)
            self.net_.eval()
            with torch.no_grad():
                val_x = val_tensor.to(self.device)
                val_recon = self.net_(val_x)
                epoch_val_loss = criterion(val_recon, val_x).item()
                self.validation_losses_.append(epoch_val_loss)

            scheduler.step(epoch_val_loss)

            # Early stopping check
            if epoch_val_loss < best_val_loss:
                best_val_loss = epoch_val_loss
                best_state = {k: v.cpu().clone() for k, v in self.net_.state_dict().items()}
                patience_counter = 0
            else:
                patience_counter += 1

            if epoch % 5 == 0 or epoch == 1:
                logger.info(f"Epoch {epoch:02d}/{max_epochs} - Train MSE: {epoch_train_loss:.6f} | Val MSE: {epoch_val_loss:.6f}")

            if patience_counter >= patience:
                logger.info(f"Early stopping triggered at epoch {epoch}. Restoring best checkpoint.")
                break

        if best_state is not None:
            self.net_.load_state_dict(best_state)

        self.is_fitted_ = True
        logger.info(f"Autoencoder training complete. Best Val MSE: {best_val_loss:.6f}")

    def calculate_reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        """
        Compute mean squared reconstruction error per flow sample:
        error_i = (1 / D) * sum_{j=1}^D (x_{i,j} - hat{x}_{i,j})^2
        """
        if not self.is_fitted_:
            raise RuntimeError("Autoencoder must be fitted before computing reconstruction errors.")

        self.net_.eval()
        with torch.no_grad():
            x_tensor = torch.tensor(X, dtype=torch.float32).to(self.device)
            recon = self.net_(x_tensor)
            # Per-sample MSE across features
            mse = torch.mean((x_tensor - recon) ** 2, dim=1).cpu().numpy()
        return mse

    def determine_anomaly_threshold(
        self,
        X_val: np.ndarray,
        y_val: np.ndarray,
        strategy: str = "val_f1_optimal",
    ) -> float:
        """
        Determine anomaly detection threshold using VALIDATION data ONLY.
        Never touches test data labels.
        """
        errors = self.calculate_reconstruction_errors(X_val)

        # Baseline statistics on benign validation samples
        benign_val_errors = errors[y_val == 0]
        self.benign_val_mean_error_ = float(np.mean(benign_val_errors))
        self.benign_val_std_error_ = float(np.std(benign_val_errors))

        if strategy == "val_f1_optimal":
            # Search threshold candidates across percentiles of validation errors
            candidates = np.percentile(errors, np.linspace(1, 99, 100))
            best_f1 = -1.0
            best_thresh = float(candidates[0])

            for thresh in candidates:
                preds = (errors >= thresh).astype(int)
                score = f1_score(y_val, preds, zero_division=0)
                if score > best_f1:
                    best_f1 = score
                    best_thresh = float(thresh)

            self.threshold_ = best_thresh
            self.threshold_strategy_ = f"val_f1_optimal (Val F1: {best_f1:.4f})"
        elif strategy == "3_sigma":
            self.threshold_ = self.benign_val_mean_error_ + 3.0 * self.benign_val_std_error_
            self.threshold_strategy_ = "3_sigma_benign_val"
        else:  # 95th percentile
            self.threshold_ = float(np.percentile(benign_val_errors, 95))
            self.threshold_strategy_ = "95th_percentile_benign_val"

        logger.info(
            f"Determined anomaly threshold: {self.threshold_:.6f} via {self.threshold_strategy_}"
        )
        return self.threshold_

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Binary anomaly prediction: 1 if error >= threshold, else 0."""
        errors = self.calculate_reconstruction_errors(X)
        return (errors >= self.threshold_).astype(int)

    def predict_anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """Continuous anomaly score (raw reconstruction error)."""
        return self.calculate_reconstruction_errors(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Convert reconstruction error into normalized probability via sigmoid:
        p(attack) = 1 / (1 + exp(-k * (error - threshold) / std))
        """
        errors = self.calculate_reconstruction_errors(X)
        scale = max(self.benign_val_std_error_, 1e-6)
        z = (errors - self.threshold_) / scale
        probs_attack = 1.0 / (1.0 + np.exp(-np.clip(z, -15, 15)))
        probs_benign = 1.0 - probs_attack
        return np.column_stack([probs_benign, probs_attack])

    def save(self, model_path: Path, metadata_path: Path):
        """Persist PyTorch model weights and threshold metadata."""
        model_path = Path(model_path)
        metadata_path = Path(metadata_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.parent.mkdir(parents=True, exist_ok=True)

        torch.save(self.net_.state_dict(), model_path)

        meta = {
            "model_type": "FlowAutoencoder",
            "input_dim": self.input_dim_,
            "latent_dim": self.latent_dim,
            "threshold": self.threshold_,
            "threshold_strategy": self.threshold_strategy_,
            "benign_val_mean_error": self.benign_val_mean_error_,
            "benign_val_std_error": self.benign_val_std_error_,
            "learning_rate": self.learning_rate,
            "random_seed": self.random_seed,
        }
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    @classmethod
    def load(cls, model_path: Path, metadata_path: Path, device: str = "cpu") -> "CyberSentinelAutoencoder":
        """Load trained autoencoder and calibrated threshold."""
        with open(metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        instance = cls(
            latent_dim=meta["latent_dim"],
            learning_rate=meta["learning_rate"],
            device=device,
            random_seed=meta["random_seed"],
        )
        instance.input_dim_ = meta["input_dim"]
        instance.threshold_ = meta["threshold"]
        instance.threshold_strategy_ = meta["threshold_strategy"]
        instance.benign_val_mean_error_ = meta["benign_val_mean_error"]
        instance.benign_val_std_error_ = meta["benign_val_std_error"]

        instance.net_ = FlowAutoencoderNet(input_dim=instance.input_dim_, latent_dim=instance.latent_dim).to(instance.device)
        instance.net_.load_state_dict(torch.load(model_path, map_location=instance.device))
        instance.net_.eval()
        instance.is_fitted_ = True
        return instance

