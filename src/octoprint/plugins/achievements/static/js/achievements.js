$(function () {
    function AchievementsViewModel(parameters) {
        var self = this;

        self.loginState = parameters[0];
        self.access = parameters[1];

        self.stats = undefined;
        self.statsFetched = ko.observable(false);
        self.dummy = ko.observable();

        self.achievements = ko.observableArray([]);
        self.hiddenAchievements = ko.observable();
        self.achievedAchievements = ko.observable();
        self.totalAchievements = ko.observable();

        self.collectingSince = ko.pureComputed(() => {
            self.dummy();
            if (!self.statsFetched()) {
                return "n/a";
            }

            return `${formatDate(self.stats.created())} (${formatTimeAgo(
                self.stats.created()
            )})`;
        });

        self.collectionVersion = ko.pureComputed(() => {
            if (!self.statsFetched()) {
                return "n/a";
            }
            return `OctoPrint ${self.stats.created_version()}`;
        });

        self.prints = ko.pureComputed(() => {
            if (!self.statsFetched()) {
                return "n/a";
            }
            if (self.stats.prints_started() === 0) {
                return gettext("No prints yet");
            }
            return _.sprintf(gettext("%(prints)s (%(finished)s finished)"), {
                prints: this.stats.prints_started(),
                finished: self.stats.prints_finished()
            });
        });

        self.duration = ko.pureComputed(() => {
            if (!self.statsFetched()) {
                return "n/a";
            }
            if (!self.stats.print_duration_finished()) {
                return _.sprintf(gettext("%(total)s"), {
                    total: formatDuration(self.stats.print_duration_total())
                });
            } else {
                return _.sprintf(gettext("%(total)s (%(finished)s finished)"), {
                    total: formatDuration(self.stats.print_duration_total()),
                    finished: formatDuration(self.stats.print_duration_finished())
                });
            }
        });

        self.longestPrint = ko.pureComputed(() => {
            self.dummy();
            if (!self.statsFetched()) {
                return "n/a";
            }
            return _.sprintf(
                gettext("%(duration)s (finished on %(date)s, %(timeSince)s)"),
                {
                    duration: formatDuration(self.stats.longest_print_duration()),
                    date: formatDate(self.stats.longest_print_date()),
                    timeSince: formatTimeAgo(self.stats.longest_print_date())
                }
            );
        });

        self.hiddenAchievementsText = ko.pureComputed(() => {
            return _.sprintf(gettext("... and %(count)s hidden achievements!"), {
                count: self.hiddenAchievements()
            });
        });

        self.requestData = () => {
            if (
                !self.loginState.hasPermission(
                    self.access.permissions.PLUGIN_ACHIEVEMENTS_VIEW
                )
            ) {
                return;
            }
            OctoPrint.plugins.achievements.get().done(self.fromResponse);
        };

        self.fromResponse = (response) => {
            self.fromStatsResponse(response.stats);
            self.fromAchievementsResponse(response.achievements);

            const achieved = _.filter(
                self.achievements(),
                (achievement) => achievement.achieved
            ).length;
            self.achievedAchievements(achieved);
            self.hiddenAchievements(response.hidden_achievements);
            self.totalAchievements(
                response.achievements.length + response.hidden_achievements
            );
        };

        self.fromStatsResponse = (response) => {
            if (self.stats === undefined) {
                self.stats = ko.mapping.fromJS(response);
                self.statsFetched(true);
            } else {
                ko.mapping.fromJS(response, self.stats);
            }
        };

        self.fromAchievementsResponse = (response) => {
            self.achievements(response);
        };

        self.CALLS_TO_ACTION = [
            gettext(
                'Enjoying OctoPrint? Looks like it! <a href="%(url)s" target="_blank" rel="noopener noreferer">It might be time to give something back then</a> - thank you!'
            ),
            gettext(
                'Getting value from OctoPrint? <a href="%(url)s" target="_blank" rel="noopener noreferer">Then please consider supporting its sole maintainer with a donation</a> - thank you!'
            ),
            gettext(
                'Has OctoPrint helped you enjoy your printer more? <a href="%(url)s" target="_blank" rel="noopener noreferer">Then please consider supporting its continued development</a> - thank you!'
            )
        ];
        self.showAchievement = (achievement) => {
            let html = `<div class="achievement"><div class="achievement-logo"><svg viewBox="0 0 24 24"><use href="#achievement-logo-${achievement.logo}"></use></svg></div><div class="achievement-content"><strong>${achievement.name}</strong><br />${achievement.description}</div></div>`;
            if (achievement.nag) {
                const idx = Math.floor(Math.random() * self.CALLS_TO_ACTION.length);
                const cta = self.CALLS_TO_ACTION[idx];
                html +=
                    "<p class='achievement-nag'>" +
                    _.sprintf(cta, {
                        url: "https://octoprint.org/support-octoprint/?utm_source=octoprint&utm_medium=achievement_popup&utm_campaign=funding"
                    }) +
                    "</p>";
            }
            html +=
                `<small class="achievement-link"><a href="javascript:void(0)" onclick="OctoPrint.coreui.viewmodels.aboutViewModel.show('about_plugin_achievements')">` +
                gettext("Show all achievements...") +
                "</a></small>";

            const options = {
                title: gettext("Achievement unlocked!"),
                text: html,
                type: "success",
                icon: "icon-star",
                hide: false,
                addclass: "achievement-popup"
            };
            new PNotify(options);
        };

        self.triggerTestAchievement = (nag) => {
            self.showAchievement({
                name: "Test Achievement",
                description: "I am a test achievement.",
                logo: "trophy",
                nag: !!nag
            });
        };

        self.onDataUpdaterPluginMessage = function (plugin, data) {
            if (plugin !== "achievements") {
                return;
            }

            if (
                !self.loginState.hasPermission(
                    self.access.permissions.PLUGIN_ACHIEVEMENTS_VIEW
                )
            ) {
                return;
            }

            if (!data.type) {
                return;
            }

            if (data.type === "achievement") {
                self.showAchievement(data);
                self.requestData();
            }
        };

        self.onServerReconnect = self.onUserLoggedIn = () => {
            if (
                !self.loginState.hasPermission(
                    self.access.permissions.PLUGIN_ACHIEVEMENTS_VIEW
                )
            ) {
                return;
            }
            self.requestData();
        };

        self.onAboutShown = () => {
            self.dummy.notifySubscribers();
        };
    }

    OCTOPRINT_VIEWMODELS.push({
        construct: AchievementsViewModel,
        dependencies: ["loginStateViewModel", "accessViewModel"],
        elements: ["#about_plugin_achievements", "#about_plugin_achievements_2"]
    });
});
