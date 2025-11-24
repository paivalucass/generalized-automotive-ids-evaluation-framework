import os
import torch
import random
import typing
import datetime

import pandas as pd
import numpy as np

from torch import nn

from sklearn.model_selection import KFold

from . import abstract_model_train_validate
from custom_metrics import timing, storage

class PytorchAutoencoderTrainValidation(abstract_model_train_validate.AbstractModelTrainValidate):
    """
    Training loop adapted to autoencoders.
    Expects `model` to be an autoencoder module whose forward(x) returns (x_recon, latent)
    or simply x_recon. This class will use MSELoss to train reconstruction.
    """

    def __init__(self, model, model_config_dict: typing.Dict):
        self._model = model

        self._model_name = model_config_dict['model_name']
        # criterion name in config is ignored for autoencoder; we'll use MSELoss
        self._model_specs_dict = model_config_dict

        hyperparameters_dict = model_config_dict.get('hyperparameters', {})
        self._learning_rate = hyperparameters_dict['learning_rate']
        self._batch_size = hyperparameters_dict['batch_size']
        self._num_epochs = hyperparameters_dict['num_epochs']

        self._evaluation_metrics = []           # will hold [fold, mean_val_loss]
        self._train_validation_losses = []      # will hold [fold, epoch, train_loss, val_loss]

        self._run_id = f"{datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S')}_pytorch_ae_train"
        art_path = model_config_dict['paths']['models_output_path']
        self._artifacts_path = f"{art_path}/{self._run_id}"

        if not os.path.exists(self._artifacts_path):
            os.makedirs(self._artifacts_path)
            print("Artifacts output directory created successfully")

        self._metrics_output_path = f"{self._artifacts_path}/metrics"
        if not os.path.exists(self._metrics_output_path):
            os.makedirs(self._metrics_output_path)
            print("Metrics output directory created successfully")

        self._models_output_path = f"{self._artifacts_path}/models"
        if not os.path.exists(self._models_output_path):
            os.makedirs(self._models_output_path)
            print("Models output directory created successfully")

        self._early_stopping_patience = hyperparameters_dict.get('early_stopping_patience', 10)
        self._best_val_loss = float("inf")
        self._epochs_without_improvement = 0

    def __seed_all(self, seed):
        if not seed:
            seed = 10
        print("[ Using Seed : ", seed, " ]")
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        torch.cuda.manual_seed(seed)
        np.random.seed(seed)
        random.seed(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False

    def __seed_worker(self, worker_id):
        worker_seed = torch.initial_seed() % 2**32
        np.random.seed(worker_seed)
        random.seed(worker_seed)

    def __reset_weights(self, m):
        if isinstance(m, nn.Conv2d) or isinstance(m, nn.Linear):
            m.reset_parameters()

    def __save_model_state_dict(self, fold=None):
        self._model.eval()
        if fold is not None:
            output_filename = f"{self._models_output_path}/pytorch_ae_{self._model_name}_{fold}.pt"
        else:
            output_filename = f"{self._models_output_path}/pytorch_ae_{self._model_name}_entire_dataset.pt"
        torch.save(self._model.state_dict(), output_filename)

    def __check_early_stopping(self, val_loss) -> int:
        ret = 0
        if val_loss < self._best_val_loss:
            self._best_val_loss = val_loss
            self._epochs_without_improvement = 0
        else:
            self._epochs_without_improvement += 1
        if self._epochs_without_improvement >= self._early_stopping_patience:
            ret = -1
        return ret

    def __reset_early_stopping(self):
        self._best_val_loss = float("inf")
        self._epochs_without_improvement = 0

    def __get_sample_input(self, dataloader, device):
        try:
            sample_batch = next(iter(dataloader))
            sample_input = sample_batch[0]
            sample_input = sample_input.float().to(device)
        except StopIteration:
            sample_input = torch.randn(1, 1, 32, 32, dtype=torch.float).to(device)
        return sample_input

    def __train_model(self, criterion, device, trainloader, fold, epoch) -> float:
        self._model.train()
        running_loss = 0.0

        self._model = self._model.to(device)
        optimizer = torch.optim.Adam(self._model.parameters(), lr=self._learning_rate)

        for batch_idx, (data, target) in enumerate(trainloader):

            # ------ NORMALIZE INPUT ------
            data = data.float().to(device) / 15.0
            target = target.float().to(device) / 15.0
            # ---------------------------------

            optimizer.zero_grad()

            out = self._model(data)
            recon = out[0] if isinstance(out, (tuple, list)) else out

            loss = criterion(recon, target)
            loss.backward()
            optimizer.step()

            running_loss += loss.item()

            if batch_idx % 1000 == 0:
                print(f"Train Fold: {fold} \t Epoch: {epoch} \t Batch: {batch_idx} \t Loss: {loss.item():.6f}")

        avg_loss = running_loss / len(trainloader)
        return avg_loss


    def __validate_model(self, criterion, device, valloader, fold, epoch) -> typing.Tuple[int, float]:
        self._model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for data, target in valloader:

                # ------ NORMALIZE INPUT ------
                data = data.float().to(device) / 15.0
                target = target.float().to(device) / 15.0
                # ---------------------------------

                out = self._model(data)
                recon = out[0] if isinstance(out, (tuple, list)) else out
                val_loss += criterion(recon, target).item()

        val_loss = val_loss / len(valloader)
        ret = self.__check_early_stopping(val_loss)
        return ret, val_loss


    def __test_model(self, device, testloader, fold):
        self._model.eval()
        errors = []
        with torch.no_grad():
            for data, target in testloader:

                # ------ NORMALIZE INPUT ------
                data = data.float().to(device) / 15.0
                # target unused, but normalize for consistency
                # ---------------------------------

                out = self._model(data)
                recon = out[0] if isinstance(out, (tuple, list)) else out

                batch_errors = torch.mean(
                    (recon - data) ** 2,
                    dim=tuple(range(1, recon.dim()))
                ).cpu().numpy()

                errors.extend(batch_errors.tolist())

        errors_arr = np.array(errors)
        np.save(f"{self._metrics_output_path}/reconstruction_errors_fold_{fold}.npy", errors_arr)

        mean_error = float(np.mean(errors_arr)) if errors_arr.size > 0 else float("nan")
        self._evaluation_metrics.append([fold, mean_error])


    def execute(self, train_data):
        """
        train_data: list of (X_i, y_i) like before. For training AE we will use only X.
        We'll build AE dataset as (x, x) so DataLoader yields (input, target=input).
        """
        # Seed & RNG
        self.__seed_all(0)
        g = torch.Generator()
        g.manual_seed(42)

        device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

        # Use MSE for reconstruction
        criterion = nn.MSELoss()

        # Prepare AE dataset - using only X (first element of train_data)
        X_only = [item[0] for item in train_data]   # each item[0] expected shape (C, H, W) or similar
        n_samples = len(X_only)
        if n_samples == 0:
            raise RuntimeError("No training samples provided to autoencoder trainer.")

        # Build pairs (x, x) so DataLoader yields (input, target)
        ae_pairs = [(x, x) for x in X_only]

        # KFold splits (not Stratified)
        kf = KFold(n_splits=5, shuffle=True, random_state=1)

        # DataLoader collate function (sends tensors to GPU if available)
        def collate_gpu(batch):
            # batch is list of tuples (x_np, x_np)
            x_list, t_list = zip(*batch)
            x = torch.utils.data.dataloader.default_collate(x_list)
            t = torch.utils.data.dataloader.default_collate(t_list)
            if device.type.startswith("cuda"):
                return x.to(device), t.to(device)
            else:
                return x, t

        # Convert to numpy-backed list as before and iterate folds
        indices = np.arange(n_samples)
        for fold, (train_idx, val_idx) in enumerate(kf.split(indices)):
            print('------------fold no---------{}----------------------'.format(fold))

            # Create subset objects (keep as lists of tuples)
            train_pairs = [ae_pairs[i] for i in train_idx]
            val_pairs = [ae_pairs[i] for i in val_idx]

            trainloader = torch.utils.data.DataLoader(train_pairs, batch_size=self._batch_size,
                                                      shuffle=True, generator=g, worker_init_fn=self.__seed_worker,
                                                      collate_fn=collate_gpu)
            valloader = torch.utils.data.DataLoader(val_pairs, batch_size=self._batch_size,
                                                    shuffle=False, generator=g, worker_init_fn=self.__seed_worker,
                                                    collate_fn=collate_gpu)

            # reset weights for fold
            self._model.apply(self.__reset_weights)

            # training loop
            self.__reset_early_stopping()
            for epoch in range(self._num_epochs):
                train_loss = self.__train_model(criterion, device, trainloader, fold, epoch)
                ret, val_loss = self.__validate_model(criterion, device, valloader, fold, epoch)
                self._train_validation_losses.append([fold, epoch, train_loss, val_loss])
                print(f"Fold {fold} Epoch {epoch} -> train_loss: {train_loss:.6f} val_loss: {val_loss:.6f}")
                if ret < 0:
                    print(f"Early stopping (no improvement in {self._early_stopping_patience} epochs).")
                    break

            # Save final model for fold
            self.__save_model_state_dict(fold)

            # Test (compute reconstruction errors on the validation set as a proxy)
            self.__test_model(device, valloader, fold)

            # Export metrics per fold so far
            train_val_loss_df = pd.DataFrame(self._train_validation_losses,
                                             columns=["fold", "epoch", "train_loss", "val_loss"])
            train_val_loss_df.to_csv(f"{self._metrics_output_path}/train_val_losses_{self._model_name}.csv", index=False)

            metrics_df = pd.DataFrame(self._evaluation_metrics, columns=["fold", "mean_recon_error"])
            metrics_df.to_csv(f"{self._metrics_output_path}/ae_val_metrics_{self._model_name}.csv", index=False)
