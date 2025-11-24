import os
import torch
import random
import typing
import datetime
import pandas as pd
import numpy as np

from torch import nn
from torchmetrics.classification import (
    BinaryAccuracy,
    BinaryF1Score,
    BinaryPrecision,
    BinaryRecall,
    BinaryAUROC,
    BinaryConfusionMatrix,
    BinaryROC
)

from . import abstract_model_test
from custom_metrics import timing, storage


class PytorchAutoencoderTest(abstract_model_test.AbstractModelTest):
    """
    Evaluate a trained Autoencoder model for anomaly detection.
    Uses reconstruction error and a threshold to classify samples as normal or anomalous.
    """

    def __init__(self, model, model_specs_dict: typing.Dict):
        self._model = model
        self._labeling_schema = model_specs_dict['feat_gen']['config']['labeling_schema']
        self._model_name = model_specs_dict['model_specs']['model_name']
        self._presaved_models_state_dict = model_specs_dict['model_specs']['presaved_paths']
        self._model_specs_dict = model_specs_dict['model_specs']
        self._batch_size = model_specs_dict['model_specs']['hyperparameters']['batch_size']

        # Threshold params
        self._threshold_method = model_specs_dict['model_specs']['hyperparameters'].get('threshold_method', 'std')
        self._threshold_factor = model_specs_dict['model_specs']['hyperparameters'].get('threshold_factor', 3.0)
        self._percentile = model_specs_dict['model_specs']['hyperparameters'].get('percentile', 99.5)
        self._evaluation_metrics = []
        self._confusion_matrix = None
        self._roc_metrics = None

        self._run_id = f"{datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S')}_pytorch_ae_test"
        art_path = model_specs_dict['model_specs']['paths']['metrics_output_path']
        self._artifacts_path = f"{art_path}/{self._run_id}"

        os.makedirs(self._artifacts_path, exist_ok=True)
        print("Artifacts output directory created successfully")

        self._metrics_output_path = f"{self._artifacts_path}/metrics"
        os.makedirs(self._metrics_output_path, exist_ok=True)
        print("Metrics output directory created successfully")

    # ---------- Utility Methods ---------- #

    def __seed_all(self, seed=10):
        print(f"[ Using Seed : {seed} ]")
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        np.random.seed(seed)
        random.seed(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False

    def __seed_worker(self, worker_id):
        worker_seed = torch.initial_seed() % 2**32
        np.random.seed(worker_seed)
        random.seed(worker_seed)

    def __get_sample_input(self, dataloader, device):
        try:
            sample_batch = next(iter(dataloader))
            sample_input = sample_batch[0].float().to(device) / 15.0  # ← normalize here too
        except StopIteration:
            sample_input = torch.randn(1, 1, 32, 32, dtype=torch.float).to(device)
        return sample_input

    def __compute_reconstruction_errors(self, model, dataloader, device):
        """Compute per-sample reconstruction MSE with normalization."""
        model.eval()
        errors, labels = [], []
        with torch.no_grad():
            for data, target in dataloader:

                # ------------ NORMALIZE ------------
                data = data.float().to(device) / 15.0
                # -----------------------------------

                target = target.float().to(device)
                out = model(data)
                recon = out[0] if isinstance(out, (tuple, list)) else out
                batch_errors = torch.mean((recon - data) ** 2,
                                          dim=tuple(range(1, recon.dim()))).cpu().numpy()
                errors.extend(batch_errors.tolist())
                labels.extend(target.cpu().numpy())
        return np.array(errors), np.array(labels)

    def __compute_threshold(self, errors_train: np.ndarray):
        """Compute threshold from training reconstruction errors."""
        if self._threshold_method == "percentile":
            thr = np.percentile(errors_train, self._percentile)
        elif self._threshold_method == "std":
            thr = errors_train.mean() + self._threshold_factor * errors_train.std()
        elif self._threshold_method == "mean":
            thr = errors_train.mean()
        else:
            raise ValueError(f"Unknown threshold method: {self._threshold_method}")
        print(f"→ Using threshold: {thr:.6f}")
        return thr

    # ---------- Testing Procedure ---------- #

    def __test_model(self, model, device, testloader, threshold, fold):
        model.eval()

        accuracy_metric = BinaryAccuracy().to(device)
        f1_metric = BinaryF1Score().to(device)
        precision_metric = BinaryPrecision().to(device)
        recall_metric = BinaryRecall().to(device)
        auc_metric = BinaryAUROC().to(device)
        confusion_metric = BinaryConfusionMatrix().to(device)
        roc_metric = BinaryROC(thresholds=1000).to(device)

        y_true, y_pred, errors = [], [], []

        with torch.no_grad():
            for data, target in testloader:

                # ------------ NORMALIZE ------------
                data = data.float().to(device) / 15.0
                # -----------------------------------

                target = target.to(device)
                target_int = target.long()

                out = model(data)
                recon = out[0] if isinstance(out, (tuple, list)) else out
                batch_errors = torch.mean((recon - data) ** 2,
                                          dim=tuple(range(1, recon.dim())))

                preds = (batch_errors > threshold).float()  # 1 = anomaly

                y_true.append(target.cpu().numpy())
                y_pred.append(preds.cpu().numpy())
                errors.append(batch_errors.cpu().numpy())

                accuracy_metric.update(preds, target_int)
                f1_metric.update(preds, target_int)
                precision_metric.update(preds, target_int)
                recall_metric.update(preds, target_int)
                auc_metric.update(preds, target_int)
                roc_metric.update(preds, target_int)

        y_true = np.concatenate(y_true)
        y_pred = np.concatenate(y_pred)
        errors = np.concatenate(errors)

        acc = accuracy_metric.compute().cpu().numpy()
        f1 = f1_metric.compute().cpu().numpy()
        prec = precision_metric.compute().cpu().numpy()
        recall = recall_metric.compute().cpu().numpy()
        auc = auc_metric.compute().cpu().numpy()

        conf = confusion_metric(
            torch.tensor(y_pred, device=device),
            torch.tensor(y_true, device=device)
        ).cpu().numpy()

        fpr, tpr, thresholds = roc_metric(
            torch.tensor(y_pred, device=device),
            torch.tensor(y_true, device=device)
        )

        roc_metrics = torch.cat(
            (fpr.reshape(-1, 1), tpr.reshape(-1, 1), thresholds.reshape(-1, 1)),
            dim=1
        ).cpu().numpy()

        dummy_input = self.__get_sample_input(testloader, device)
        timing_func = timing.pytorch_inference_time_gpu if device.type == "cuda" else timing.pytorch_inference_time_cpu
        inference_time = timing_func(model, dummy_input)

        self._evaluation_metrics.append([fold, acc, prec, recall, f1, auc, inference_time])
        self._confusion_matrix = conf
        self._roc_metrics = roc_metrics

        np.save(f"{self._metrics_output_path}/reconstruction_errors_fold_{fold}.npy", errors)
        np.save(f"{self._metrics_output_path}/y_true_fold_{fold}.npy", y_true)
        np.save(f"{self._metrics_output_path}/y_pred_fold_{fold}.npy", y_pred)

    def execute(self, data, train_errors_path: str = None):
        """
        Run inference on AE model(s).
        - data: list of (x, y) pairs (y = 0 normal, 1 anomaly)
        """

        def collate_gpu(batch):
            x, t = torch.utils.data.dataloader.default_collate(batch)
            device_target = "cuda:0" if torch.cuda.is_available() else "cpu"
            return x.to(device=device_target), t.to(device=device_target)

        self.__seed_all(0)
        g = torch.Generator()
        g.manual_seed(42)

        device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        
        self._model.to(device)

        testloader = torch.utils.data.DataLoader(
            data,
            batch_size=self._batch_size,
            generator=g,
            worker_init_fn=self.__seed_worker,
            collate_fn=collate_gpu
        )

        # ---------------- STEP 1: Load or estimate training reconstruction errors ----------------
        if train_errors_path and os.path.exists(train_errors_path):
            errors_train = np.load(train_errors_path)

        else:
            print("WARNING: Training reconstruction errors not provided — estimating threshold from (normalized) test data.")

            # ------- NORMALIZE full dataset for threshold estimation -------
            all_X = torch.stack([torch.tensor(d[0]) for d in data]).float().to(device) / 15.0
            # -----------------------------------------------------------------

            with torch.no_grad():
                out = self._model(all_X)
                recon = out[0] if isinstance(out, (tuple, list)) else out
                errors_train = torch.mean((recon - all_X) ** 2,
                                          dim=tuple(range(1, recon.dim()))).cpu().numpy()

        threshold = self.__compute_threshold(errors_train)

        # ---------------- STEP 2: Evaluate each saved model ----------------
        for fold_index, model_path in self._presaved_models_state_dict.items():
            print(f"------------ Testing Fold {fold_index} ------------")
            self._model.load_state_dict(torch.load(model_path, map_location=device))
            self._model.to(device)

            self.__test_model(self._model, device, testloader, threshold, fold_index)

            metrics_df = pd.DataFrame(self._evaluation_metrics,
                                      columns=["fold", "acc", "prec", "recall", "f1", "roc_auc", "inference_time"])
            metrics_df.to_csv(
                f"{self._metrics_output_path}/test_metrics_{self._labeling_schema}_{self._model_name}_fold_{fold_index}.csv",
                index=False
            )

            conf_df = pd.DataFrame(self._confusion_matrix)
            conf_df.to_csv(
                f"{self._metrics_output_path}/confusion_matrix_{self._labeling_schema}_fold_{fold_index}_{self._model_name}.csv",
                index=False
            )

            roc_df = pd.DataFrame(self._roc_metrics, columns=["fpr", "tpr", "thresholds"])
            roc_df.to_csv(
                f"{self._metrics_output_path}/roc_metrics_{self._labeling_schema}_fold_{fold_index}_{self._model_name}.csv",
                index=False
            )
